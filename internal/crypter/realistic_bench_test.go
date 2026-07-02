package crypter

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"io"
	"os"
	"testing"
)

// This benchmark measures real memory usage by writing to io.Discard
// instead of bytes.Buffer (which causes massive reallocations).
func BenchmarkRealisticMemory(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1MB", 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
		{"64MB", 64 * 1024 * 1024},
	}

	for _, size := range sizes {
		b.Run("Encrypt_"+size.name, func(b *testing.B) {
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
				// Use io.Discard to avoid bytes.Buffer reallocations
				crypter.Encrypt(iv, reader, io.Discard)
			}
		})

		b.Run("Decrypt_"+size.name, func(b *testing.B) {
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
				// Use io.Discard to avoid bytes.Buffer reallocations
				crypter.Decrypt(reader, io.Discard)
			}
		})
	}
}

// Test with actual files to show real-world memory usage.
func BenchmarkFileOperations(b *testing.B) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	crypter, _ := NewAESCrypter(key)

	// Create a 10MB test file
	testFile := b.TempDir() + "/test.bin"
	encFile := b.TempDir() + "/test.enc"
	decFile := b.TempDir() + "/test.dec"

	plaintext := make([]byte, 10*1024*1024)
	io.ReadFull(rand.Reader, plaintext)
	os.WriteFile(testFile, plaintext, 0o644)

	iv := make([]byte, aes.BlockSize)
	io.ReadFull(rand.Reader, iv)

	b.Run("Encrypt_File_10MB", func(b *testing.B) {
		b.SetBytes(10 * 1024 * 1024)
		b.ResetTimer()

		for range b.N {
			in, _ := os.Open(testFile)
			out, _ := os.Create(encFile)
			crypter.Encrypt(iv, in, out)
			in.Close()
			out.Close()
		}
	})

	// Encrypt once for decrypt benchmark
	in, _ := os.Open(testFile)
	out, _ := os.Create(encFile)
	crypter.Encrypt(iv, in, out)
	in.Close()
	out.Close()

	b.Run("Decrypt_File_10MB", func(b *testing.B) {
		b.SetBytes(10 * 1024 * 1024)
		b.ResetTimer()

		for range b.N {
			in, _ := os.Open(encFile)
			out, _ := os.Create(decFile)
			crypter.Decrypt(in, out)
			in.Close()
			out.Close()
		}
	})
}
