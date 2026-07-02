package crypter

import (
	"bytes"
	"crypto/aes"
	"io"
	"testing"
)

func BenchmarkBufferSizes(b *testing.B) {
	bufferSizes := []struct {
		name string
		size int
	}{
		{name: "4KB", size: 4 * 1024},
		{name: "8KB", size: 8 * 1024},
		{name: "16KB", size: 16 * 1024},
		{name: "32KB", size: 32 * 1024},
		{name: "64KB", size: 64 * 1024},
		{name: "128KB", size: 128 * 1024},
		{name: "256KB", size: 256 * 1024},
		{name: "512KB", size: 512 * 1024},
		{name: "1MB", size: 1024 * 1024},
	}
	const dataSize = 64 * 1024 * 1024
	plaintext := make([]byte, dataSize)
	iv := make([]byte, aes.BlockSize)

	for _, bufferSize := range bufferSizes {
		crypter, err := newAESCrypter(make([]byte, 32), bufferSize.size)
		if err != nil {
			b.Fatal(err)
		}

		b.Run("Encrypt_"+bufferSize.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(dataSize)
			for range b.N {
				if err := crypter.Encrypt(iv, bytes.NewReader(plaintext), io.Discard); err != nil {
					b.Fatal(err)
				}
			}
		})

		ciphertext := encryptBenchmarkData(b, crypter, dataSize)
		b.Run("Decrypt_"+bufferSize.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(dataSize)
			for range b.N {
				if err := crypter.Decrypt(bytes.NewReader(ciphertext), io.Discard); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
