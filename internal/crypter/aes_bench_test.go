package crypter

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"io"
	"testing"
)

func BenchmarkAESEncrypt(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"64KB", 64 * 1024},
		{"1MB", 1024 * 1024},
	}

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			// Setup
			key := make([]byte, 32)
			io.ReadFull(rand.Reader, key)
			crypter, _ := NewAESCrypter(key)

			plaintext := make([]byte, size.size)
			io.ReadFull(rand.Reader, plaintext)

			iv := make([]byte, aes.BlockSize)
			io.ReadFull(rand.Reader, iv)

			b.ResetTimer()
			b.SetBytes(int64(size.size))

			for range b.N {
				reader := bytes.NewReader(plaintext)
				writer := &bytes.Buffer{}
				crypter.Encrypt(iv, reader, writer)
			}
		})
	}
}

func BenchmarkAESDecrypt(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"64KB", 64 * 1024},
		{"1MB", 1024 * 1024},
	}

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			// Setup
			key := make([]byte, 32)
			io.ReadFull(rand.Reader, key)
			crypter, _ := NewAESCrypter(key)

			plaintext := make([]byte, size.size)
			io.ReadFull(rand.Reader, plaintext)

			iv := make([]byte, aes.BlockSize)
			io.ReadFull(rand.Reader, iv)

			// Encrypt once to get ciphertext
			ciphertextBuf := &bytes.Buffer{}
			crypter.Encrypt(iv, bytes.NewReader(plaintext), ciphertextBuf)
			ciphertext := ciphertextBuf.Bytes()

			b.ResetTimer()
			b.SetBytes(int64(size.size))

			for range b.N {
				reader := bytes.NewReader(ciphertext)
				writer := &bytes.Buffer{}
				crypter.Decrypt(reader, writer)
			}
		})
	}
}

func BenchmarkAESRoundTrip(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"64KB", 64 * 1024},
		{"1MB", 1024 * 1024},
	}

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			key := make([]byte, 32)
			io.ReadFull(rand.Reader, key)
			crypter, _ := NewAESCrypter(key)

			plaintext := make([]byte, size.size)
			io.ReadFull(rand.Reader, plaintext)

			iv := make([]byte, aes.BlockSize)
			io.ReadFull(rand.Reader, iv)

			b.ResetTimer()
			b.SetBytes(int64(size.size))

			for range b.N {
				// Encrypt
				encBuf := &bytes.Buffer{}
				crypter.Encrypt(iv, bytes.NewReader(plaintext), encBuf)

				// Decrypt
				decBuf := &bytes.Buffer{}
				crypter.Decrypt(encBuf, decBuf)
			}
		})
	}
}
