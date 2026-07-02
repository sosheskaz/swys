package crypter

import (
	"bytes"
	"crypto/aes"
	"testing"
)

var benchmarkSizes = []struct {
	name string
	size int
}{
	{name: "1KB", size: 1024},
	{name: "64KB", size: 64 * 1024},
	{name: "1MB", size: 1024 * 1024},
}

func BenchmarkAESEncrypt(b *testing.B) {
	for _, size := range benchmarkSizes {
		b.Run(size.name, func(b *testing.B) {
			crypter := newBenchmarkCrypter(b)
			plaintext := make([]byte, size.size)
			iv := make([]byte, aes.BlockSize)

			b.ReportAllocs()
			b.SetBytes(int64(size.size))
			b.ResetTimer()
			for range b.N {
				output := bytes.NewBuffer(make([]byte, 0, size.size+2*aes.BlockSize))
				if err := crypter.Encrypt(iv, bytes.NewReader(plaintext), output); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkAESDecrypt(b *testing.B) {
	for _, size := range benchmarkSizes {
		b.Run(size.name, func(b *testing.B) {
			crypter := newBenchmarkCrypter(b)
			ciphertext := encryptBenchmarkData(b, crypter, size.size)

			b.ReportAllocs()
			b.SetBytes(int64(size.size))
			b.ResetTimer()
			for range b.N {
				output := bytes.NewBuffer(make([]byte, 0, size.size))
				if err := crypter.Decrypt(bytes.NewReader(ciphertext), output); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkAESRoundTrip(b *testing.B) {
	for _, size := range benchmarkSizes {
		b.Run(size.name, func(b *testing.B) {
			crypter := newBenchmarkCrypter(b)
			plaintext := make([]byte, size.size)
			iv := make([]byte, aes.BlockSize)

			b.ReportAllocs()
			b.SetBytes(int64(size.size))
			b.ResetTimer()
			for range b.N {
				ciphertext := bytes.NewBuffer(make([]byte, 0, size.size+2*aes.BlockSize))
				if err := crypter.Encrypt(iv, bytes.NewReader(plaintext), ciphertext); err != nil {
					b.Fatal(err)
				}
				decrypted := bytes.NewBuffer(make([]byte, 0, size.size))
				if err := crypter.Decrypt(ciphertext, decrypted); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func newBenchmarkCrypter(b *testing.B) *AESCrypter {
	b.Helper()
	crypter, err := NewAESCrypter(make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}
	return crypter
}

func encryptBenchmarkData(b *testing.B, crypter *AESCrypter, size int) []byte {
	b.Helper()
	var output bytes.Buffer
	output.Grow(size + 2*aes.BlockSize)
	if err := crypter.Encrypt(make([]byte, aes.BlockSize), bytes.NewReader(make([]byte, size)), &output); err != nil {
		b.Fatal(err)
	}
	return output.Bytes()
}
