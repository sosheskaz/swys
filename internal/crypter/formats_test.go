package crypter

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"testing/iotest"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
)

var errAESInput = errors.New("AES input failed")

func TestAESFormatRoundTripsBoundaryLengths(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	primitive, err := subtle.NewAESGCMHKDF(key, "SHA256", 32, 64, 0)
	require.NoError(t, err)
	for _, length := range []int{0, 1, 63, 64, 65, 256} {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			t.Parallel()
			plaintext := bytes.Repeat([]byte{0x72}, length)
			var pgpWire bytes.Buffer
			require.NoError(t, EncryptOpenPGP(key, 64, bytes.NewReader(plaintext), &pgpWire))
			reader, err := PrepareOpenPGP(key, bytes.NewReader(pgpWire.Bytes()))
			require.NoError(t, err)
			var opened bytes.Buffer
			require.NoError(t, reader.CopyTo(&opened))
			require.True(t, bytes.Equal(plaintext, opened.Bytes()), "OpenPGP plaintext differs at length %d", length)

			var tinkWire bytes.Buffer
			require.NoError(t, EncryptTink(primitive, bytes.NewReader(plaintext), &tinkWire, nil))
			decrypting, err := primitive.NewDecryptingReader(bytes.NewReader(tinkWire.Bytes()), nil)
			require.NoError(t, err)
			openedBytes, err := io.ReadAll(decrypting)
			require.NoError(t, err)
			require.Equal(t, plaintext, openedBytes)
		})
	}
}

func TestAESInterruptedEncryptionCannotProduceCompleteCiphertext(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	primitive, err := subtle.NewAESGCMHKDF(key, "SHA256", 32, 64, 0)
	require.NoError(t, err)
	for _, test := range []struct {
		encrypt func(io.Reader, io.Writer) error
		open    func([]byte) ([]byte, error)
		name    string
	}{
		{
			name: "OpenPGP",
			encrypt: func(input io.Reader, output io.Writer) error {
				return EncryptOpenPGP(key, 64, input, output)
			},
			open: func(wire []byte) ([]byte, error) {
				reader, err := PrepareOpenPGP(key, bytes.NewReader(wire))
				if err != nil {
					return nil, err
				}
				var plaintext bytes.Buffer
				err = reader.CopyTo(&plaintext)
				return plaintext.Bytes(), err
			},
		},
		{
			name: "Tink",
			encrypt: func(input io.Reader, output io.Writer) error {
				return EncryptTink(primitive, input, output, nil)
			},
			open: func(wire []byte) ([]byte, error) {
				reader, err := primitive.NewDecryptingReader(bytes.NewReader(wire), nil)
				if err != nil {
					return nil, fmt.Errorf("open Tink reader: %w", err)
				}
				return io.ReadAll(reader)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := io.MultiReader(bytes.NewReader([]byte("interrupted payload")), iotest.ErrReader(errAESInput))
			var wire bytes.Buffer
			err := test.encrypt(input, &wire)
			require.ErrorIs(t, err, errAESInput)
			opened, openErr := test.open(wire.Bytes())
			require.Error(t, openErr, "interrupted encryption produced a valid shortened message %q", opened)
		})
	}
}

func TestAESFormatsPreserveIOErrors(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	primitive, err := subtle.NewAESGCMHKDF(key, "SHA256", 32, 64, 0)
	require.NoError(t, err)
	for _, test := range []struct {
		encrypt func(io.Reader, io.Writer) error
		open    func(io.Reader, io.Writer) error
		name    string
	}{
		{
			name: "OpenPGP",
			encrypt: func(input io.Reader, output io.Writer) error {
				return EncryptOpenPGP(key, 64, input, output)
			},
			open: func(input io.Reader, output io.Writer) error {
				reader, err := PrepareOpenPGP(key, input)
				if err != nil {
					return err
				}
				return reader.CopyTo(output)
			},
		},
		{
			name: "Tink",
			encrypt: func(input io.Reader, output io.Writer) error {
				return EncryptTink(primitive, input, output, nil)
			},
			open: func(input io.Reader, output io.Writer) error {
				reader, err := primitive.NewDecryptingReader(input, nil)
				if err != nil {
					return fmt.Errorf("open Tink reader: %w", err)
				}
				_, err = io.Copy(output, reader)
				if err != nil {
					return fmt.Errorf("read Tink plaintext: %w", err)
				}
				return nil
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plaintext := bytes.Repeat([]byte{0x73}, 256)
			var wire bytes.Buffer
			require.NoError(t, test.encrypt(bytes.NewReader(plaintext), &wire))

			err := test.encrypt(bytes.NewReader(plaintext), aesErrorWriter{errAESInput})
			require.ErrorIs(t, err, errAESInput)
			err = test.open(bytes.NewReader(wire.Bytes()), aesErrorWriter{errAESInput})
			require.ErrorIs(t, err, errAESInput)
			err = test.encrypt(bytes.NewReader(plaintext), aesShortWriter{})
			require.ErrorIs(t, err, io.ErrShortWrite)
			err = test.open(bytes.NewReader(wire.Bytes()), aesShortWriter{})
			require.ErrorIs(t, err, io.ErrShortWrite)
			err = test.encrypt(bytes.NewReader(plaintext), &aesFirstShortWriter{})
			require.ErrorIs(t, err, io.ErrShortWrite)

			input := io.MultiReader(bytes.NewReader(wire.Bytes()[:len(wire.Bytes())-1]), iotest.ErrReader(errAESInput))
			err = test.open(input, io.Discard)
			require.ErrorIs(t, err, errAESInput)
		})
	}
}

type aesErrorWriter struct{ err error }

func (w aesErrorWriter) Write([]byte) (int, error) { return 0, w.err }

type aesShortWriter struct{}

func (aesShortWriter) Write([]byte) (int, error) { return 0, nil }

// aesFirstShortWriter drops only the first write, such as a one-byte packet tag.
type aesFirstShortWriter struct{ written bool }

func (w *aesFirstShortWriter) Write(data []byte) (int, error) {
	if !w.written {
		w.written = true
		return 0, nil
	}
	return len(data), nil
}

func TestAESFormatRejectsUnsupportedKeyAndChunk(t *testing.T) {
	t.Parallel()
	for _, keySize := range []int{0, 15, 24, 33} {
		err := EncryptOpenPGP(make([]byte, keySize), 64, bytes.NewReader(nil), io.Discard)
		require.ErrorIs(t, err, ErrInvalidAESKeySize)
	}
	for _, chunk := range []uint32{0, 63, 96, MaxOpenPGPChunkSize + 1} {
		err := EncryptOpenPGP(make([]byte, 32), chunk, bytes.NewReader(nil), io.Discard)
		require.Error(t, err)
	}
}

func TestOpenPGPReleasesOnlyAuthenticatedChunks(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	plaintext := bytes.Repeat([]byte{0x73}, 256)
	var encrypted bytes.Buffer
	require.NoError(t, EncryptOpenPGP(key, 64, bytes.NewReader(plaintext), &encrypted))
	wire := encrypted.Bytes()
	require.Equal(t, byte(0xd2), wire[0])
	require.True(t, wire[1] >= 192 && wire[1] <= 223, "fixture expects a two-octet outer packet length")
	require.Equal(t, byte(2), wire[3], "fixture expects SEIPDv2")
	require.Equal(t, byte(0), wire[6], "fixture expects 64-byte AEAD chunks")
	firstCiphertext := 3 + 4 + 32
	for _, test := range []struct {
		name   string
		offset int
		first  bool
	}{
		{name: "first chunk", offset: firstCiphertext + 1, first: true},
		{name: "later chunk", offset: firstCiphertext + 64 + 16 + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			corrupted := bytes.Clone(wire)
			corrupted[test.offset] ^= 1
			reader, err := PrepareOpenPGP(key, bytes.NewReader(corrupted))
			if err != nil {
				if test.first {
					return
				}
				t.Fatal(err)
			}
			var opened bytes.Buffer
			err = reader.CopyTo(&opened)
			require.Error(t, err)
			if test.first {
				require.Empty(t, opened.Bytes(), "unauthenticated first chunk reached output")
				return
			}
			require.True(t, bytes.HasPrefix(plaintext, opened.Bytes()))
			require.Less(t, opened.Len(), len(plaintext))
		})
	}
}

func TestOpenPGPRejectsDeclaredLengthBeyondInput(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	encrypt := func(size int) []byte {
		var wire bytes.Buffer
		require.NoError(t, EncryptOpenPGP(key, 64, bytes.NewReader(bytes.Repeat([]byte{0x74}, size)), &wire))
		return wire.Bytes()
	}
	for _, test := range []struct {
		name string
		wire []byte
	}{
		{name: "one-octet definite length", wire: bumpFinalOpenPGPLength(t, encrypt(0), false)},
		{name: "two-octet final partial segment", wire: bumpFinalOpenPGPLength(t, encrypt(1000), true)},
		{name: "five-octet definite length", wire: definiteOpenPGPPacket(t, encrypt(1000), 1)},
		{name: "input ends after partial segment", wire: withoutFinalOpenPGPSegment(t, encrypt(1000))},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			reader, err := PrepareOpenPGP(key, bytes.NewReader(test.wire))
			if err == nil {
				err = reader.CopyTo(io.Discard)
			}
			require.ErrorIs(t, err, errOpenPGPTruncated)
		})
	}
	t.Run("exact five-octet definite length", func(t *testing.T) {
		t.Parallel()
		reader, err := PrepareOpenPGP(key, bytes.NewReader(definiteOpenPGPPacket(t, encrypt(1000), 0)))
		require.NoError(t, err)
		var opened bytes.Buffer
		require.NoError(t, reader.CopyTo(&opened))
		require.Equal(t, bytes.Repeat([]byte{0x74}, 1000), opened.Bytes())
	})
}

func TestOpenPGPAcceptsFinalDataWithEOF(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	// Sizes vary the outer buffer alignment so some final reads bypass it.
	for _, chunk := range []uint32{64, 1 << 10, 1 << 20} {
		t.Run(strconv.Itoa(int(chunk)), func(t *testing.T) {
			t.Parallel()
			for size := 0; size < 5000; size += 7 {
				plaintext := bytes.Repeat([]byte{0x75}, size)
				var wire bytes.Buffer
				require.NoError(t, EncryptOpenPGP(key, chunk, bytes.NewReader(plaintext), &wire))
				reader, err := PrepareOpenPGP(key, dataEOFReader{bytes.NewReader(wire.Bytes())})
				require.NoError(t, err, "size %d", size)
				var opened bytes.Buffer
				require.NoError(t, reader.CopyTo(&opened), "size %d", size)
				require.Equal(t, plaintext, opened.Bytes())
			}
		})
	}
}

// dataEOFReader returns io.EOF with the final bytes, as io.Reader permits.
type dataEOFReader struct{ reader *bytes.Reader }

func (r dataEOFReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if err == nil && r.reader.Len() == 0 {
		err = io.EOF
	}
	return n, err
}

// bumpFinalOpenPGPLength declares one more byte in the outer packet's final
// definite length than the input contains.
func bumpFinalOpenPGPLength(t *testing.T, wire []byte, partial bool) []byte {
	t.Helper()
	_, offset, header := openPGPPacketBody(t, wire)
	require.Equal(t, partial, offset > 1, "fixture partial-length framing")
	wire = bytes.Clone(wire)
	switch {
	case header == 1 && wire[offset] < 191:
		wire[offset]++
	case header == 2 && partial && wire[offset+1] < 255:
		wire[offset+1]++
	default:
		t.Fatalf("unexpected %d-octet final length at %d", header, offset)
	}
	return wire
}

// withoutFinalOpenPGPSegment ends the input after the outer packet's last
// partial segment, before its final length.
func withoutFinalOpenPGPSegment(t *testing.T, wire []byte) []byte {
	t.Helper()
	_, offset, _ := openPGPPacketBody(t, wire)
	require.Greater(t, offset, 1, "fixture expects partial-length framing")
	return wire[:offset]
}

// definiteOpenPGPPacket reframes the outer packet with a five-octet length that
// declares extra bytes beyond its body.
func definiteOpenPGPPacket(t *testing.T, wire []byte, extra uint32) []byte {
	t.Helper()
	body, _, _ := openPGPPacketBody(t, wire)
	framed := []byte{wire[0], 0xff}
	framed = binary.BigEndian.AppendUint32(framed, uint32(len(body))+extra)
	return append(framed, body...)
}

// openPGPPacketBody joins a single new-format packet's partial segments and
// returns the offset and octet count of its final definite length.
func openPGPPacketBody(t *testing.T, wire []byte) ([]byte, int, int) {
	t.Helper()
	require.Equal(t, byte(0xd2), wire[0], "fixture expects a new-format SEIPD packet")
	var body []byte
	offset := 1
	for wire[offset] >= 224 && wire[offset] < 255 {
		size := 1 << (wire[offset] & 0x1f)
		body = append(body, wire[offset+1:offset+1+size]...)
		offset += 1 + size
	}
	var size, header int
	switch first := int(wire[offset]); {
	case first < 192:
		size, header = first, 1
	case first < 224:
		size, header = (first-192)<<8+int(wire[offset+1])+192, 2
	default:
		size, header = int(binary.BigEndian.Uint32(wire[offset+1:])), 5
	}
	require.Len(t, wire, offset+header+size, "fixture expects one outer packet")
	return append(body, wire[offset+header:]...), offset, header
}

func TestOpenPGPRejectsMalformedHeaderWithoutReadingBody(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	// One MiB body with an invalid AEAD mode in the first four body bytes.
	header := []byte{0xd2, 0xff, 0, 0x10, 0, 0, 2, 9, 0x7f, 0}
	input := &countingAESReader{reader: io.MultiReader(
		bytes.NewReader(header), io.LimitReader(aesZeroReader{}, (1<<20)-4),
	)}
	_, err := PrepareOpenPGP(key, input)
	require.Error(t, err)
	require.LessOrEqual(t, input.read, 4096, "invalid packet header must not drain ciphertext body")
}

func TestOpenPGPCompressedHeaderReadIsBounded(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	var wire bytes.Buffer
	writer := encryptedTestWriter(t, &wire, key, 64)
	_, err := writer.Write([]byte{0xa3, 1}) // Indeterminate-length compressed packet using ZIP.
	require.NoError(t, err)
	writeEmptyDEFLATEBlocks(t, writer, (4<<20+64<<10)/5)
	_, err = writer.Write([]byte{1, 0, 0, 0xff, 0xff})
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	input := &countingAESReader{reader: bytes.NewReader(wire.Bytes())}
	_, err = PrepareOpenPGP(key, input)
	require.ErrorIs(t, err, errOpenPGPHeaderBudget)
	// 4096 header bytes, then a 16-byte tag peek, 512 bytes of buffering, and
	// ceil((4 MiB + 512) / 64) authenticated 80-byte chunks.
	require.LessOrEqual(t, input.read, 4096+16+512+65544*80,
		"compressed header drained ciphertext beyond one decoder block before output preparation")
}

func TestOpenPGPStreamsSmallChunkCompressedLiteral(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	plaintext := make([]byte, 64<<10)
	_, err := rand.New(rand.NewSource(2)).Read(plaintext)
	require.NoError(t, err)
	for _, algorithm := range []packet.CompressionAlgo{packet.CompressionZIP, packet.CompressionZLIB} {
		for _, chunk := range []uint64{64, 1 << 10, 16 << 10} {
			t.Run(fmt.Sprintf("%d/%d", algorithm, chunk), func(t *testing.T) {
				t.Parallel()
				var wire bytes.Buffer
				compressed, err := packet.SerializeCompressed(encryptedTestWriter(t, &wire, key, chunk), algorithm, nil)
				require.NoError(t, err)
				literal, err := packet.SerializeLiteral(compressed, true, "", 0)
				require.NoError(t, err)
				_, err = literal.Write(plaintext)
				require.NoError(t, err)
				require.NoError(t, literal.Close())

				reader, err := PrepareOpenPGP(key, bytes.NewReader(wire.Bytes()))
				require.NoError(t, err)
				var opened bytes.Buffer
				require.NoError(t, reader.CopyTo(&opened))
				require.Equal(t, plaintext, opened.Bytes())
			})
		}
	}
}

func TestOpenPGPStreamsSmallChunkBZip2Literal(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	fixture, err := os.ReadFile(filepath.Join("testdata", "openpgp", "literal-sha256-16k.bz2"))
	require.NoError(t, err)
	var plaintext []byte
	for i := range uint32(512) {
		digest := sha256.Sum256(binary.BigEndian.AppendUint32(nil, i))
		plaintext = append(plaintext, digest[:]...)
	}
	for _, nested := range []bool{false, true} {
		for _, chunk := range []uint64{64, 1 << 10} {
			t.Run(fmt.Sprintf("nested=%t/%d", nested, chunk), func(t *testing.T) {
				t.Parallel()
				var wire bytes.Buffer
				writer := encryptedTestWriter(t, &wire, key, chunk)
				if nested {
					compressed, err := packet.SerializeCompressed(writer, packet.CompressionZIP, nil)
					require.NoError(t, err)
					writer = compressed
				}
				// Indeterminate-length compressed packet using BZip2.
				_, err := writer.Write(append([]byte{0xa3, 3}, fixture...))
				require.NoError(t, err)
				require.NoError(t, writer.Close())

				reader, err := PrepareOpenPGP(key, bytes.NewReader(wire.Bytes()))
				require.NoError(t, err)
				var opened bytes.Buffer
				require.NoError(t, reader.CopyTo(&opened))
				require.Equal(t, plaintext, opened.Bytes())
			})
		}
	}
}

func TestOpenPGPLayerBudgetCrossedAfterLiteralHeaderFails(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	// The literal header fits within the inner layer budget but its stored
	// block does not, so DEFLATE yields the header before reporting the limit.
	const stored = 1024
	var wire bytes.Buffer
	writer, err := packet.SerializeCompressed(encryptedTestWriter(t, &wire, key, 1<<20),
		packet.CompressionZIP, &packet.CompressionConfig{Level: 9})
	require.NoError(t, err)
	_, err = writer.Write([]byte{0xa3, 1}) // Indeterminate-length compressed packet using ZIP.
	require.NoError(t, err)
	writeEmptyDEFLATEBlocks(t, writer, (openPGPLayerReadLimit-2-5-9-64)/5)
	const bodyLength = stored - 3 // Two-octet literal length covers six fields and stored-9 data bytes.
	block := []byte{
		1, byte(stored & 0xff), byte(stored >> 8), ^byte(stored & 0xff), ^byte(stored >> 8), // Final stored DEFLATE block.
		0xcb, byte((bodyLength-192)>>8 + 192), byte((bodyLength - 192) & 0xff), 'b', 0, 0, 0, 0, 0,
	}
	_, err = writer.Write(append(block, make([]byte, stored-9)...))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	_, err = PrepareOpenPGP(key, bytes.NewReader(wire.Bytes()))
	require.ErrorIs(t, err, errOpenPGPHeaderBudget)
}

func TestOpenPGPStreamsLargeCompressedLiteral(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	plaintext := make([]byte, int(MaxOpenPGPChunkSize)+17)
	_, err := rand.New(rand.NewSource(1)).Read(plaintext)
	require.NoError(t, err)
	for _, chunk := range []uint64{1 << 20, MaxOpenPGPChunkSize} {
		for _, layers := range []int{1, 2} {
			t.Run(fmt.Sprintf("%d/%d-layers", chunk, layers), func(t *testing.T) {
				t.Parallel()
				var wire bytes.Buffer
				writer, err := packet.SerializeSymmetricallyEncrypted(&wire, 0, true,
					packet.CipherSuite{Cipher: packet.CipherAES256, Mode: packet.AEADModeGCM},
					key, &packet.Config{AEADConfig: &packet.AEADConfig{ChunkSize: chunk}})
				require.NoError(t, err)
				for range layers {
					writer, err = packet.SerializeCompressed(writer, packet.CompressionZIP, nil)
					require.NoError(t, err)
				}
				literal, err := packet.SerializeLiteral(writer, true, "", 0)
				require.NoError(t, err)
				n, err := literal.Write(plaintext)
				require.NoError(t, err)
				require.Equal(t, len(plaintext), n)
				require.NoError(t, literal.Close())

				reader, err := PrepareOpenPGP(key, bytes.NewReader(wire.Bytes()))
				require.NoError(t, err)
				var opened bytes.Buffer
				require.NoError(t, reader.CopyTo(&opened))
				require.Equal(t, plaintext, opened.Bytes())
			})
		}
	}
}

func TestOpenPGPNestedCompressedHeaderReadIsBounded(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	for _, test := range []struct {
		chunk  uint64
		layers int
	}{{chunk: 1 << 20, layers: 2}, {chunk: 64, layers: 3}} {
		t.Run(fmt.Sprintf("%d-layers", test.layers), func(t *testing.T) {
			t.Parallel()
			wire := nestedEmptyBlockWire(t, key, test.chunk, test.layers, 8<<20)
			// Fit under the ciphertext cap so only per-layer budgets can reject it.
			require.Less(t, len(wire), max(8192, int(test.chunk)+4096))
			_, err := PrepareOpenPGP(key, bytes.NewReader(wire))
			require.ErrorIs(t, err, errOpenPGPHeaderBudget)
		})
	}
}

// nestedEmptyBlockWire nests an innermost compressed packet of empty DEFLATE
// blocks and a final literal inside layers-1 highly compressed ZIP packets.
func nestedEmptyBlockWire(t *testing.T, key []byte, chunk uint64, layers, emptyBytes int) []byte {
	t.Helper()
	var wire bytes.Buffer
	writer := encryptedTestWriter(t, &wire, key, chunk)
	var err error
	for range layers - 1 {
		writer, err = packet.SerializeCompressed(writer, packet.CompressionZIP, &packet.CompressionConfig{Level: 9})
		require.NoError(t, err)
	}
	_, err = writer.Write([]byte{0xa3, 1}) // Indeterminate-length compressed packet using ZIP.
	require.NoError(t, err)
	writeEmptyDEFLATEBlocks(t, writer, emptyBytes/5)
	literal := []byte{0xcb, 6, 'b', 0, 0, 0, 0, 0} // Empty binary literal packet.
	_, err = writer.Write(append([]byte{1, byte(len(literal)), 0, ^byte(len(literal)), 0xff}, literal...))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return wire.Bytes()
}

func encryptedTestWriter(t *testing.T, wire *bytes.Buffer, key []byte, chunk uint64) io.WriteCloser {
	t.Helper()
	writer, err := packet.SerializeSymmetricallyEncrypted(wire, 0, true,
		packet.CipherSuite{Cipher: packet.CipherAES256, Mode: packet.AEADModeGCM},
		key, &packet.Config{AEADConfig: &packet.AEADConfig{ChunkSize: chunk}})
	require.NoError(t, err)
	return writer
}

// writeEmptyDEFLATEBlocks writes count non-final empty stored DEFLATE blocks.
func writeEmptyDEFLATEBlocks(t *testing.T, writer io.Writer, count int) {
	t.Helper()
	blocks := bytes.Repeat([]byte{0, 0, 0, 0xff, 0xff}, 4096)
	for count > 0 {
		n := min(count, 4096)
		_, err := writer.Write(blocks[:n*5])
		require.NoError(t, err)
		count -= n
	}
}

type countingAESReader struct {
	reader io.Reader
	read   int
}

func (r *countingAESReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.read += n
	return n, err //nolint:wrapcheck // io.Reader must preserve io.EOF identity.
}
