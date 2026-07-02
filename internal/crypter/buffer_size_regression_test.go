package crypter

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestAESCrypterBufferBoundaries(t *testing.T) {
	bufferSizes := []struct {
		name string
		size int
	}{
		{name: "4KB", size: 4 * 1024},
		{name: "production default", size: cryptBufferSize},
		{name: "1MB", size: 1024 * 1024},
	}
	for _, bufferSize := range bufferSizes {
		t.Run(bufferSize.name, func(t *testing.T) {
			crypter, err := newAESCrypter(make([]byte, 32), bufferSize.size)
			if err != nil {
				t.Fatal(err)
			}

			payloadSizes := []int{
				0,
				aes.BlockSize - 1,
				aes.BlockSize,
				aes.BlockSize + 1,
				bufferSize.size - 1,
				bufferSize.size,
				bufferSize.size + 1,
			}
			for _, payloadSize := range payloadSizes {
				plaintext := bytes.Repeat([]byte{0x5a}, payloadSize)
				var ciphertext bytes.Buffer
				if err := crypter.Encrypt(make([]byte, aes.BlockSize), bytes.NewReader(plaintext), &ciphertext); err != nil {
					t.Fatalf("encrypt %d bytes: %v", payloadSize, err)
				}
				var decrypted bytes.Buffer
				if err := crypter.Decrypt(&ciphertext, &decrypted); err != nil {
					t.Fatalf("decrypt %d bytes: %v", payloadSize, err)
				}
				if !bytes.Equal(decrypted.Bytes(), plaintext) {
					t.Fatalf("round trip mismatch for %d bytes", payloadSize)
				}
			}
		})
	}
}
