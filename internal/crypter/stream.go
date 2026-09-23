package crypter

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
)

const (
	// MinAESChunkSize is the smallest supported plaintext segment size.
	MinAESChunkSize = 64
	// MaxAESChunkSize is the largest supported plaintext segment size.
	MaxAESChunkSize = 64 * 1024 * 1024
	// DefaultAESChunkSize is the CLI's default plaintext segment size.
	DefaultAESChunkSize = 1024 * 1024
	aesStreamHeaderSize = 16
)

var (
	aesStreamMagic               = []byte("NPCENC\r\n")
	aesStreamAADPrefix           = []byte("npc/aes-gcm-stream/v1\x00")
	errInvalidAESStreamHeader    = errors.New("invalid AES stream header")
	errAESStreamSuiteKeyMismatch = errors.New("AES stream suite does not match supplied key size")
	errInvalidAESStreamChunkSize = errors.New("invalid AES stream chunk size")
)

// AESStreamingCrypter uses the version 1 NPC envelope around Tink AES-GCM-HKDF streaming.
type AESStreamingCrypter struct {
	key   []byte
	suite byte
}

// NewAESStreamingCrypter constructs a streaming crypter with an AES-128 or AES-256 key.
func NewAESStreamingCrypter(key []byte) (*AESStreamingCrypter, error) {
	if len(key) != 16 && len(key) != 32 {
		return nil, fmt.Errorf("create AES stream: %w", aes.KeySizeError(len(key)))
	}
	suite := byte(1)
	if len(key) == 32 {
		suite = 2
	}
	return &AESStreamingCrypter{key: bytes.Clone(key), suite: suite}, nil
}

// Encrypt writes an authenticated, versioned stream and finalizes it after source EOF.
func (a *AESStreamingCrypter) Encrypt(plaintext io.Reader, ciphertext io.Writer, aad []byte, chunkSize uint32) error {
	if chunkSize < MinAESChunkSize || chunkSize > MaxAESChunkSize {
		return fmt.Errorf("%w %d", errInvalidAESStreamChunkSize, chunkSize)
	}
	primitive, err := subtle.NewAESGCMHKDF(a.key, "SHA256", len(a.key), int(chunkSize)+16, 0)
	if err != nil {
		return fmt.Errorf("create AES stream: %w", err)
	}
	var header [aesStreamHeaderSize]byte
	copy(header[:], aesStreamMagic)
	header[8], header[9] = 1, a.suite
	binary.BigEndian.PutUint16(header[10:12], aesStreamHeaderSize)
	binary.BigEndian.PutUint32(header[12:16], chunkSize)
	if err := writeAll(ciphertext, header[:]); err != nil {
		return fmt.Errorf("write AES stream header: %w", err)
	}
	writer, err := primitive.NewEncryptingWriter(shortWriteChecker{ciphertext}, streamAAD(header[:], aad))
	if err != nil {
		return fmt.Errorf("start AES stream: %w", err)
	}
	if _, err := io.Copy(writer, plaintext); err != nil {
		return fmt.Errorf("read plaintext or write ciphertext: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finalize AES stream: %w", err)
	}
	return nil
}

// Decrypt releases only authenticated plaintext segments.
func (a *AESStreamingCrypter) Decrypt(ciphertext io.Reader, plaintext io.Writer, aad []byte) error {
	var header [aesStreamHeaderSize]byte
	if _, err := io.ReadFull(ciphertext, header[:]); err != nil {
		return fmt.Errorf("read AES stream header: %w", err)
	}
	if !bytes.Equal(header[:8], aesStreamMagic) {
		return fmt.Errorf("%w: expected NPC stream prefix; for legacy GCM ciphertext, select --raw", errInvalidAESStreamHeader)
	}
	if header[8] != 1 || (header[9] != 1 && header[9] != 2) || binary.BigEndian.Uint16(header[10:12]) != aesStreamHeaderSize {
		return errInvalidAESStreamHeader
	}
	if header[9] != a.suite {
		return errAESStreamSuiteKeyMismatch
	}
	chunkSize := binary.BigEndian.Uint32(header[12:16])
	if chunkSize < MinAESChunkSize || chunkSize > MaxAESChunkSize {
		return fmt.Errorf("%w %d", errInvalidAESStreamChunkSize, chunkSize)
	}
	primitive, err := subtle.NewAESGCMHKDF(a.key, "SHA256", len(a.key), int(chunkSize)+16, 0)
	if err != nil {
		return fmt.Errorf("create AES stream: %w", err)
	}
	// Tink formats header read errors without wrapping. Read its bounded header
	// first so errors from caller-owned sources retain their identity.
	tinkHeader := make([]byte, primitive.HeaderLength())
	if _, err := io.ReadFull(ciphertext, tinkHeader); err != nil {
		return fmt.Errorf("read Tink stream header: %w", err)
	}
	reader, err := primitive.NewDecryptingReader(io.MultiReader(bytes.NewReader(tinkHeader), ciphertext), streamAAD(header[:], aad))
	if err != nil {
		return fmt.Errorf("start AES stream: %w", err)
	}
	if _, err := io.Copy(shortWriteChecker{plaintext}, reader); err != nil {
		return fmt.Errorf("decrypt AES stream: %w", err)
	}
	return nil
}

func streamAAD(header, aad []byte) []byte {
	bound := make([]byte, 0, len(aesStreamAADPrefix)+len(header)+len(aad))
	bound = append(bound, aesStreamAADPrefix...)
	bound = append(bound, header...)
	return append(bound, aad...)
}

type shortWriteChecker struct{ io.Writer }

func (w shortWriteChecker) Write(data []byte) (int, error) {
	n, err := w.Writer.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return n, err
}
