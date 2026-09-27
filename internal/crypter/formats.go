package crypter

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	pgp "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// MaxOpenPGPChunkSize is the largest OpenPGP AEAD plaintext chunk NPC writes or
// accepts.
const MaxOpenPGPChunkSize = 4 << 20

var (
	errOpenPGPChunk        = errors.New("invalid OpenPGP chunk size")
	errOpenPGPPacket       = errors.New("invalid OpenPGP packet")
	errOpenPGPHeaderBudget = errors.New("OpenPGP header exceeds preparation limit")
	errOpenPGPTruncated    = errors.New("unexpected end of OpenPGP input")
)

// openPGPLayerReadLimit bounds reads from each packet layer before the literal
// header. Decoders consume a whole unit before yielding output: a DEFLATE yield
// covers at most a 32 KiB window at no more than 16 bits per byte, and a BZip2
// block holds at most 900,001 symbols of at most 20 bits, about 2.3 MB. BZip2
// code-length tables may be padded without bound, so a block padded past this
// limit is rejected.
const openPGPLayerReadLimit = 4 << 20

// preparationBudget fails reads beyond its limit instead of reporting EOF, so
// an exhausted budget cannot pass for a short final AEAD chunk or a truncated
// block whose partial output a decoder flushes.
type preparationBudget struct {
	reader    io.Reader
	remaining int64
	exceeded  bool
}

func (b *preparationBudget) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		b.exceeded = true
		return 0, errOpenPGPHeaderBudget
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.reader.Read(p)
	b.remaining -= int64(n)
	return n, err //nolint:wrapcheck // io.Reader must preserve io.EOF identity.
}

func (b *preparationBudget) lift() { b.remaining = math.MaxInt64 }

// inputEOF reports input EOF as truncation. Packet body readers stop at their
// declared length without reading further, but pass through a short input as
// an EOF the AEAD reader accepts as its final chunk. EOF returned with data is
// deferred to the next read so the data is not reported as truncated.
type inputEOF struct {
	reader io.Reader
	eof    bool
}

func (r *inputEOF) Read(p []byte) (int, error) {
	if r.eof {
		return 0, errOpenPGPTruncated
	}
	n, err := r.reader.Read(p)
	if err == io.EOF {
		r.eof = true
		if n > 0 {
			return n, nil
		}
		return 0, errOpenPGPTruncated
	}
	return n, err //nolint:wrapcheck // io.Reader must preserve error identity.
}

// EncryptOpenPGP writes an RFC 9580 AEAD packet stream using a supplied session key.
func EncryptOpenPGP(key []byte, chunk uint32, input io.Reader, output io.Writer) error {
	if len(key) != 16 && len(key) != 32 {
		return ErrInvalidAESKeySize
	}
	if chunk < 64 || chunk > MaxOpenPGPChunkSize || chunk&(chunk-1) != 0 {
		return fmt.Errorf("%w %d", errOpenPGPChunk, chunk)
	}
	algorithm := constants.AES128
	if len(key) == 32 {
		algorithm = constants.AES256
	}
	p := profile.RFC9580()
	p.AeadEncryption = &packet.AEADConfig{DefaultMode: packet.AEADModeGCM, ChunkSize: uint64(chunk)}
	handle, err := pgp.PGPWithProfile(p).Encryption().
		SessionKey(pgp.NewSessionKeyFromTokenWithAead(key, algorithm, true)).
		CompressWith(constants.NoCompression).New()
	if err != nil {
		return fmt.Errorf("prepare OpenPGP encryption: %w", err)
	}
	writer, err := handle.EncryptingWriter(shortWriterChecker{output}, pgp.Bytes)
	if err != nil {
		return fmt.Errorf("open OpenPGP writer: %w", err)
	}
	if _, err := io.Copy(writer, input); err != nil {
		return fmt.Errorf("encrypt OpenPGP input: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finalize OpenPGP stream: %w", err)
	}
	return nil
}

// OpenPGPReader validates the outer packet header before output is opened.
// Its CopyTo method authenticates each chunk and requires inner and outer EOF.
type OpenPGPReader struct {
	literal io.Reader
	body    io.ReadCloser
	readers []*bufio.Reader // outer reader first, then each inner compression layer
}

// PrepareOpenPGP validates the packet header and prepares authenticated reading.
func PrepareOpenPGP(key []byte, input io.Reader) (*OpenPGPReader, error) {
	if len(key) != 16 && len(key) != 32 {
		return nil, ErrInvalidAESKeySize
	}
	source := &preparationBudget{reader: &inputEOF{reader: input}, remaining: 4096}
	outer := bufio.NewReaderSize(source, 512)
	if err := expectPacketTag(outer, 18); err != nil {
		return nil, err
	}
	value, err := packet.Read(outer)
	if err != nil {
		if source.exceeded {
			return nil, errOpenPGPHeaderBudget
		}
		return nil, fmt.Errorf("read OpenPGP header: %w", err)
	}
	encrypted, ok := value.(*packet.SymmetricallyEncrypted)
	if !ok || !encrypted.IntegrityProtected || encrypted.Version != 2 {
		return nil, fmt.Errorf("%w: requires RFC 9580 SEIPDv2", errOpenPGPPacket)
	}
	expected := packet.CipherAES128
	if len(key) == 32 {
		expected = packet.CipherAES256
	}
	if encrypted.Cipher != expected || encrypted.ChunkSizeByte > 16 {
		return nil, fmt.Errorf("%w: unsupported AES parameters", errOpenPGPPacket)
	}
	// The AEAD reader peeks one tag, then authenticates whole chunks. Allow the
	// ciphertext for one layer budget of plaintext plus inner and outer buffering
	// until the literal header is identified.
	chunk := int64(1) << (encrypted.ChunkSizeByte + 6)
	tag := int64(encrypted.Mode.TagLength())
	source.remaining = tag + (openPGPLayerReadLimit+512+chunk-1)/chunk*(chunk+tag) + 512
	body, err := encrypted.Decrypt(expected, key)
	if err != nil {
		if source.exceeded {
			return nil, errOpenPGPHeaderBudget
		}
		return nil, fmt.Errorf("decrypt OpenPGP header: %w", err)
	}
	return prepareOpenPGPContents(body, outer, source)
}

func prepareOpenPGPContents(body io.ReadCloser, outer *bufio.Reader, source *preparationBudget) (*OpenPGPReader, error) {
	current := io.Reader(body)
	readers := []*bufio.Reader{outer}
	// Decompressed layers can amplify a capped ciphertext, so each one keeps its
	// read budget until the literal header is identified.
	budgets := []*preparationBudget{source}
	for layer := range 5 {
		budget := &preparationBudget{reader: current, remaining: openPGPLayerReadLimit}
		budgets = append(budgets, budget)
		inner := bufio.NewReaderSize(budget, 512)
		innerPacket, err := readInnerPacket(inner)
		// A decoder may flush a header from a block truncated by the budget.
		if slices.ContainsFunc(budgets, func(b *preparationBudget) bool { return b.exceeded }) {
			return nil, errors.Join(errOpenPGPHeaderBudget, body.Close())
		}
		if err != nil {
			return nil, errors.Join(err, body.Close())
		}
		if layer == 0 {
			// The source budget already bounds reads from the decrypted body.
			budget.lift()
		}
		readers = append(readers, inner)
		switch typed := innerPacket.(type) {
		case *packet.LiteralData:
			for _, b := range budgets {
				b.lift()
			}
			return &OpenPGPReader{body: body, readers: readers, literal: typed.Body}, nil
		case *packet.Compressed:
			current = typed.Body
		default:
			return nil, errors.Join(fmt.Errorf("%w: unsupported inner packet", errOpenPGPPacket), body.Close())
		}
	}
	return nil, errors.Join(fmt.Errorf("%w: compression nesting exceeds four layers", errOpenPGPPacket), body.Close())
}

func readInnerPacket(reader *bufio.Reader) (packet.Packet, error) {
	if err := expectPacketTags(reader, 8, 11); err != nil {
		return nil, err
	}
	value, err := packet.Read(reader)
	if err != nil {
		return nil, fmt.Errorf("read OpenPGP inner packet: %w", err)
	}
	return value, nil
}

func expectPacketTag(reader *bufio.Reader, tag byte) error { return expectPacketTags(reader, tag) }

func expectPacketTags(reader *bufio.Reader, allowed ...byte) error {
	header, err := reader.Peek(1)
	if err != nil {
		return fmt.Errorf("read OpenPGP packet: %w", err)
	}
	if header[0]&0x80 == 0 {
		return fmt.Errorf("%w: packet header", errOpenPGPPacket)
	}
	tag := header[0] & 0x3f
	if header[0]&0x40 == 0 {
		tag = (header[0] >> 2) & 0x0f
	}
	for _, allowedTag := range allowed {
		if tag == allowedTag {
			return nil
		}
	}
	return fmt.Errorf("%w: unexpected tag %d", errOpenPGPPacket, tag)
}

// CopyTo writes authenticated plaintext and verifies final tag and packet EOF.
func (r *OpenPGPReader) CopyTo(output io.Writer) error {
	_, copyErr := io.Copy(output, r.literal)
	if copyErr != nil {
		return fmt.Errorf("read OpenPGP literal: %w", copyErr)
	}
	for i := len(r.readers) - 1; i > 0; i-- {
		_, err := r.readers[i].Peek(1)
		if err != io.EOF {
			if err == nil {
				return fmt.Errorf("%w: extra inner packet", errOpenPGPPacket)
			}
			return fmt.Errorf("read OpenPGP inner packet end: %w", err)
		}
	}
	if err := r.body.Close(); err != nil {
		return fmt.Errorf("verify OpenPGP final tag: %w", err)
	}
	_, err := r.readers[0].Peek(1)
	switch {
	case errors.Is(err, errOpenPGPTruncated):
		return nil // Input ends after the packet's declared length.
	case err == nil:
		return fmt.Errorf("%w: extra outer packet", errOpenPGPPacket)
	default:
		return fmt.Errorf("read OpenPGP outer packet end: %w", err)
	}
}

// EncryptTink writes a native bare Tink AES-GCM-HKDF ciphertext stream.
func EncryptTink(primitive tink.StreamingAEAD, input io.Reader, output io.Writer, aad []byte) error {
	writer, err := primitive.NewEncryptingWriter(shortWriterChecker{output}, aad)
	if err != nil {
		return fmt.Errorf("open Tink writer: %w", err)
	}
	if _, err := io.Copy(writer, input); err != nil {
		return fmt.Errorf("encrypt Tink input: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finalize Tink stream: %w", err)
	}
	return nil
}

type shortWriterChecker struct{ output io.Writer }

func (w shortWriterChecker) Write(data []byte) (int, error) {
	n, err := w.output.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return n, err
}
