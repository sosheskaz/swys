package crypter

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"io"
	"strings"
	"testing"
)

// TestAESCrypterRoundTrip tests basic encryption/decryption round trip.
func TestAESCrypterRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		plaintext string
		keySize   int
	}{
		{
			name:      "small message with 128-bit key",
			plaintext: "Hello, World!",
			keySize:   16,
		},
		{
			name:      "small message with 256-bit key",
			plaintext: "Hello, World!",
			keySize:   32,
		},
		{
			name:      "empty message",
			plaintext: "",
			keySize:   16,
		},
		{
			name:      "message exactly one block",
			plaintext: "1234567890123456", // 16 bytes
			keySize:   16,
		},
		{
			name:      "message less than one block",
			plaintext: "short",
			keySize:   16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			if _, err := io.ReadFull(rand.Reader, key); err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			crypter, err := NewAESCrypter(key)
			if err != nil {
				t.Fatalf("failed to create crypter: %v", err)
			}

			iv := make([]byte, aes.BlockSize)
			if _, err := io.ReadFull(rand.Reader, iv); err != nil {
				t.Fatalf("failed to generate IV: %v", err)
			}

			// Encrypt
			plainReader := strings.NewReader(tt.plaintext)
			cipherBuf := &bytes.Buffer{}
			if err := crypter.Encrypt(iv, plainReader, cipherBuf); err != nil {
				t.Fatalf("encryption failed: %v", err)
			}

			// Decrypt
			decryptedBuf := &bytes.Buffer{}
			if err := crypter.Decrypt(cipherBuf, decryptedBuf); err != nil {
				t.Fatalf("decryption failed: %v", err)
			}

			// Verify
			if got := decryptedBuf.String(); got != tt.plaintext {
				t.Errorf("round trip failed:\nwant: %q (%d bytes)\ngot:  %q (%d bytes)",
					tt.plaintext, len(tt.plaintext), got, len(got))
				t.Logf("got bytes: %v", []byte(got))
			}
		})
	}
}

// TestAESCrypterLargeData tests encryption/decryption with data larger than buffer size
// This exposes issue #2 (buffer corruption bug) and #4 (decrypt buffer resize).
func TestAESCrypterLargeData(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{
			name: "just over one buffer (65KB)",
			size: 65 * 1024,
		},
		{
			name: "multiple buffers (200KB)",
			size: 200 * 1024,
		},
		{
			name: "exactly two buffers (128KB)",
			size: 128 * 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate random plaintext
			plaintext := make([]byte, tt.size)
			if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
				t.Fatalf("failed to generate plaintext: %v", err)
			}

			// Generate key and IV
			key := make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, key); err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			crypter, err := NewAESCrypter(key)
			if err != nil {
				t.Fatalf("failed to create crypter: %v", err)
			}

			iv := make([]byte, aes.BlockSize)
			if _, err := io.ReadFull(rand.Reader, iv); err != nil {
				t.Fatalf("failed to generate IV: %v", err)
			}

			// Encrypt
			plainReader := bytes.NewReader(plaintext)
			cipherBuf := &bytes.Buffer{}
			if err := crypter.Encrypt(iv, plainReader, cipherBuf); err != nil {
				t.Fatalf("encryption failed: %v", err)
			}

			// Decrypt
			decryptedBuf := &bytes.Buffer{}
			if err := crypter.Decrypt(cipherBuf, decryptedBuf); err != nil {
				t.Fatalf("decryption failed: %v", err)
			}

			// Verify
			decrypted := decryptedBuf.Bytes()
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("round trip failed for %d bytes", tt.size)
				t.Logf("plaintext length: %d", len(plaintext))
				t.Logf("decrypted length: %d", len(decrypted))

				// Show where they first differ
				minLen := len(plaintext)
				if len(decrypted) < minLen {
					minLen = len(decrypted)
				}
				for i := range minLen {
					if plaintext[i] != decrypted[i] {
						t.Logf("first difference at byte %d: want %02x, got %02x", i, plaintext[i], decrypted[i])
						break
					}
				}
			}
		})
	}
}

// TestAESCrypterPaddingRemoval specifically tests that PKCS#7 padding is removed
// This exposes issue #3 (missing padding removal).
func TestAESCrypterPaddingRemoval(t *testing.T) {
	tests := []struct {
		name      string
		plaintext string
	}{
		{
			name:      "message requiring 1 byte padding",
			plaintext: strings.Repeat("a", 15), // 15 bytes, needs 1 byte padding
		},
		{
			name:      "message requiring 8 bytes padding",
			plaintext: strings.Repeat("b", 8), // 8 bytes, needs 8 bytes padding
		},
		{
			name:      "message requiring full block padding",
			plaintext: strings.Repeat("c", 16), // 16 bytes (1 full block), needs 16 bytes padding
		},
		{
			name:      "message requiring 15 bytes padding",
			plaintext: "x", // 1 byte, needs 15 bytes padding
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, 16)
			if _, err := io.ReadFull(rand.Reader, key); err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			crypter, err := NewAESCrypter(key)
			if err != nil {
				t.Fatalf("failed to create crypter: %v", err)
			}

			iv := make([]byte, aes.BlockSize)
			if _, err := io.ReadFull(rand.Reader, iv); err != nil {
				t.Fatalf("failed to generate IV: %v", err)
			}

			// Encrypt
			plainReader := strings.NewReader(tt.plaintext)
			cipherBuf := &bytes.Buffer{}
			if err := crypter.Encrypt(iv, plainReader, cipherBuf); err != nil {
				t.Fatalf("encryption failed: %v", err)
			}

			// Decrypt
			decryptedBuf := &bytes.Buffer{}
			if err := crypter.Decrypt(cipherBuf, decryptedBuf); err != nil {
				t.Fatalf("decryption failed: %v", err)
			}

			// Check if padding was properly removed
			decrypted := decryptedBuf.Bytes()
			if len(decrypted) != len(tt.plaintext) {
				t.Errorf("padding not removed: want %d bytes, got %d bytes", len(tt.plaintext), len(decrypted))
				t.Logf("plaintext: %q", tt.plaintext)
				t.Logf("decrypted: %q", string(decrypted))
				if len(decrypted) > 0 {
					t.Logf("last byte value: %d (0x%02x)", decrypted[len(decrypted)-1], decrypted[len(decrypted)-1])
				}
			}

			if string(decrypted) != tt.plaintext {
				t.Errorf("decrypted content mismatch:\nwant: %q\ngot:  %q", tt.plaintext, string(decrypted))
			}
		})
	}
}

// TestAESCrypterInvalidInput tests error handling.
func TestAESCrypterInvalidInput(t *testing.T) {
	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	crypter, err := NewAESCrypter(key)
	if err != nil {
		t.Fatalf("failed to create crypter: %v", err)
	}

	t.Run("decrypt empty ciphertext", func(t *testing.T) {
		emptyBuf := &bytes.Buffer{}
		outBuf := &bytes.Buffer{}
		err := crypter.Decrypt(emptyBuf, outBuf)
		if err == nil {
			t.Error("expected error when decrypting empty ciphertext, got nil")
		}
	})

	t.Run("decrypt ciphertext smaller than IV", func(t *testing.T) {
		smallBuf := bytes.NewReader([]byte{1, 2, 3, 4, 5})
		outBuf := &bytes.Buffer{}
		err := crypter.Decrypt(smallBuf, outBuf)
		if err == nil {
			t.Error("expected error when decrypting ciphertext smaller than IV, got nil")
		}
	})
}
