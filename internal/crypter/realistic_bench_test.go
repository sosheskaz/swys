package crypter

import (
	"bytes"
	"crypto/aes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkRealisticMemory(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{name: "1MB", size: 1024 * 1024},
		{name: "10MB", size: 10 * 1024 * 1024},
		{name: "64MB", size: 64 * 1024 * 1024},
	}

	for _, size := range sizes {
		b.Run("Encrypt_"+size.name, func(b *testing.B) {
			crypter := newBenchmarkCrypter(b)
			plaintext := make([]byte, size.size)
			iv := make([]byte, aes.BlockSize)

			b.ReportAllocs()
			b.SetBytes(int64(size.size))
			b.ResetTimer()
			for range b.N {
				if err := crypter.Encrypt(iv, bytes.NewReader(plaintext), io.Discard); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run("Decrypt_"+size.name, func(b *testing.B) {
			crypter := newBenchmarkCrypter(b)
			ciphertext := encryptBenchmarkData(b, crypter, size.size)

			b.ReportAllocs()
			b.SetBytes(int64(size.size))
			b.ResetTimer()
			for range b.N {
				if err := crypter.Decrypt(bytes.NewReader(ciphertext), io.Discard); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run("GCM_Encrypt_"+size.name, func(b *testing.B) {
			crypter := newBenchmarkGCMCrypter(b)
			plaintext := make([]byte, size.size)

			b.ReportAllocs()
			b.SetBytes(int64(size.size))
			b.ResetTimer()
			for range b.N {
				if err := crypter.Encrypt(bytes.NewReader(plaintext), io.Discard, nil); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run("GCM_Decrypt_"+size.name, func(b *testing.B) {
			crypter := newBenchmarkGCMCrypter(b)
			ciphertext := encryptGCMBenchmarkData(b, crypter, size.size)

			b.ReportAllocs()
			b.SetBytes(int64(size.size))
			b.ResetTimer()
			for range b.N {
				if err := crypter.Decrypt(bytes.NewReader(ciphertext), io.Discard, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkFileOperations(b *testing.B) {
	const dataSize = 10 * 1024 * 1024
	crypter := newBenchmarkCrypter(b)
	iv := make([]byte, aes.BlockSize)
	tempDir := b.TempDir()
	plainPath := filepath.Join(tempDir, "plain.bin")
	cipherPath := filepath.Join(tempDir, "cipher.bin")
	decryptedPath := filepath.Join(tempDir, "decrypted.bin")
	if err := os.WriteFile(plainPath, make([]byte, dataSize), 0o600); err != nil {
		b.Fatal(err)
	}

	b.Run("Encrypt_File_10MB", func(b *testing.B) {
		b.SetBytes(dataSize)
		for range b.N {
			if err := encryptFile(crypter, iv, plainPath, cipherPath); err != nil {
				b.Fatal(err)
			}
		}
	})

	if err := encryptFile(crypter, iv, plainPath, cipherPath); err != nil {
		b.Fatal(err)
	}
	b.Run("Decrypt_File_10MB", func(b *testing.B) {
		b.SetBytes(dataSize)
		for range b.N {
			if err := decryptFile(crypter, cipherPath, decryptedPath); err != nil {
				b.Fatal(err)
			}
		}
	})

	gcmCrypter := newBenchmarkGCMCrypter(b)
	gcmCipherPath := filepath.Join(tempDir, "gcm-cipher.bin")
	gcmDecryptedPath := filepath.Join(tempDir, "gcm-decrypted.bin")
	b.Run("GCM_Encrypt_File_10MB", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(dataSize)
		for range b.N {
			if err := encryptGCMFile(gcmCrypter, plainPath, gcmCipherPath); err != nil {
				b.Fatal(err)
			}
		}
	})

	if err := encryptGCMFile(gcmCrypter, plainPath, gcmCipherPath); err != nil {
		b.Fatal(err)
	}
	b.Run("GCM_Decrypt_File_10MB", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(dataSize)
		for range b.N {
			if err := decryptGCMFile(gcmCrypter, gcmCipherPath, gcmDecryptedPath); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func encryptFile(crypter *AESCrypter, iv []byte, inputPath, outputPath string) (runErr error) {
	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open benchmark plaintext: %w", err)
	}
	defer func() { runErr = errors.Join(runErr, input.Close()) }()

	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open benchmark ciphertext: %w", err)
	}
	defer func() { runErr = errors.Join(runErr, output.Close()) }()
	return crypter.Encrypt(iv, input, output)
}

func decryptFile(crypter *AESCrypter, inputPath, outputPath string) (runErr error) {
	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open benchmark ciphertext: %w", err)
	}
	defer func() { runErr = errors.Join(runErr, input.Close()) }()

	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open benchmark plaintext: %w", err)
	}
	defer func() { runErr = errors.Join(runErr, output.Close()) }()
	return crypter.Decrypt(input, output)
}

func encryptGCMFile(crypter *AESGCMCrypter, inputPath, outputPath string) (runErr error) {
	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open GCM benchmark plaintext: %w", err)
	}
	defer func() { runErr = errors.Join(runErr, input.Close()) }()

	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open GCM benchmark ciphertext: %w", err)
	}
	defer func() { runErr = errors.Join(runErr, output.Close()) }()
	return crypter.Encrypt(input, output, nil)
}

func decryptGCMFile(crypter *AESGCMCrypter, inputPath, outputPath string) (runErr error) {
	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open GCM benchmark ciphertext: %w", err)
	}
	defer func() { runErr = errors.Join(runErr, input.Close()) }()

	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open GCM benchmark plaintext: %w", err)
	}
	defer func() { runErr = errors.Join(runErr, output.Close()) }()
	return crypter.Decrypt(input, output, nil)
}

func newBenchmarkGCMCrypter(b *testing.B) *AESGCMCrypter {
	b.Helper()
	crypter, err := NewAESGCMCrypter(make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}
	return crypter
}

func encryptGCMBenchmarkData(b *testing.B, crypter *AESGCMCrypter, size int) []byte {
	b.Helper()
	var output bytes.Buffer
	output.Grow(size + gcmWireOverhead)
	if err := crypter.Encrypt(bytes.NewReader(make([]byte, size)), &output, nil); err != nil {
		b.Fatal(err)
	}
	return output.Bytes()
}
