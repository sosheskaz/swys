package crypter

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/sosheskaz-systems/npc/internal/sys"
)

const (
	maxGCMPlaintextSize = 64 * 1024 * 1024
	gcmWireOverhead     = 12 + 16
)

var (
	errInvalidGCMConfiguration = errors.New("invalid AES-GCM configuration")

	// ErrInputTooLarge is returned when an input exceeds the configured message limit.
	ErrInputTooLarge = errors.New("input too large")
	// ErrMalformedCiphertext is returned when ciphertext is too short to contain a nonce and tag.
	ErrMalformedCiphertext = errors.New("malformed ciphertext")
	// ErrAuthenticationFailed is returned when GCM authentication fails.
	ErrAuthenticationFailed = errors.New("authentication failed")
)

type gcmWireAEAD interface {
	Overhead() int
	Seal(dst, plaintext, aad []byte) ([]byte, error)
	Open(dst, ciphertext, aad []byte) ([]byte, error)
}

type randomNonceWireAEAD struct {
	aead cipher.AEAD
}

// Overhead returns the nonce and authentication-tag size.
func (a *randomNonceWireAEAD) Overhead() int {
	return a.aead.Overhead()
}

// Seal appends a nonce-prefixed ciphertext to dst.
func (a *randomNonceWireAEAD) Seal(dst, plaintext, aad []byte) ([]byte, error) {
	return a.aead.Seal(dst, nil, plaintext, aad), nil
}

// Open authenticates and decrypts a nonce-prefixed ciphertext.
func (a *randomNonceWireAEAD) Open(dst, ciphertext, aad []byte) ([]byte, error) {
	opened, err := a.aead.Open(dst, nil, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("open random-nonce AES-GCM ciphertext: %w", err)
	}
	return opened, nil
}

// AESGCMCrypter encrypts and decrypts nonce-prefixed AES-GCM messages.
type AESGCMCrypter struct {
	aead             gcmWireAEAD
	maxPlaintextSize int
}

// NewAESGCMCrypter constructs an AES-GCM crypter from a 16-, 24-, or 32-byte key.
func NewAESGCMCrypter(key []byte) (*AESGCMCrypter, error) {
	sys.Log().Debug("creating new AES-GCM crypter", "bits", len(key)*8)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	return newAESGCMCrypter(&randomNonceWireAEAD{aead: aead}, maxGCMPlaintextSize)
}

func newAESGCMCrypter(aead gcmWireAEAD, maxPlaintextSize int) (*AESGCMCrypter, error) {
	if aead == nil {
		return nil, fmt.Errorf("%w: nil wire AEAD", errInvalidGCMConfiguration)
	}
	if maxPlaintextSize <= 0 {
		return nil, fmt.Errorf("%w: maximum plaintext size must be positive, got %d", errInvalidGCMConfiguration, maxPlaintextSize)
	}
	if maxPlaintextSize > math.MaxInt-gcmWireOverhead {
		return nil, fmt.Errorf("%w: maximum plaintext size %d exceeds safe integer bound", errInvalidGCMConfiguration, maxPlaintextSize)
	}
	if aead.Overhead() != gcmWireOverhead {
		return nil, fmt.Errorf("%w: GCM wire overhead must be %d bytes, got %d", errInvalidGCMConfiguration, gcmWireOverhead, aead.Overhead())
	}
	return &AESGCMCrypter{aead: aead, maxPlaintextSize: maxPlaintextSize}, nil
}

// Encrypt reads and authenticates one bounded plaintext message, then writes its ciphertext.
func (a *AESGCMCrypter) Encrypt(plaintext io.Reader, ciphertext io.Writer, aad []byte) error {
	message, err := readGCMInput(plaintext, a.maxPlaintextSize)
	if err != nil {
		return fmt.Errorf("read plaintext: %w", err)
	}
	sealed, err := a.aead.Seal(make([]byte, 0, len(message)+a.aead.Overhead()), message, aad)
	if err != nil {
		return fmt.Errorf("seal plaintext: %w", err)
	}
	if err := writeAll(ciphertext, sealed); err != nil {
		return fmt.Errorf("write ciphertext: %w", err)
	}
	return nil
}

// Decrypt reads and authenticates one bounded ciphertext message, then writes its plaintext.
func (a *AESGCMCrypter) Decrypt(ciphertext io.Reader, plaintext io.Writer, aad []byte) error {
	wireLimit := a.maxPlaintextSize + a.aead.Overhead()
	message, err := readGCMInput(ciphertext, wireLimit)
	if err != nil {
		return fmt.Errorf("read ciphertext: %w", err)
	}
	if len(message) < a.aead.Overhead() {
		return fmt.Errorf("%w: got %d bytes, need at least %d", ErrMalformedCiphertext, len(message), a.aead.Overhead())
	}
	opened, err := a.aead.Open(make([]byte, 0, len(message)-a.aead.Overhead()), message, aad)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAuthenticationFailed, err)
	}
	if err := writeAll(plaintext, opened); err != nil {
		return fmt.Errorf("write plaintext: %w", err)
	}
	return nil
}

func readGCMInput(reader io.Reader, maximum int) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, int64(maximum)+1))
	if err != nil {
		return nil, fmt.Errorf("read bounded input: %w", err)
	}
	if len(data) > maximum {
		return nil, fmt.Errorf("%w: maximum is %d bytes", ErrInputTooLarge, maximum)
	}
	return data, nil
}
