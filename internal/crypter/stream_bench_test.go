package crypter

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkAESStreaming(b *testing.B) {
	key := bytes.Repeat([]byte{0x42}, 32)
	stream, err := NewAESStreamingCrypter(key)
	if err != nil {
		b.Fatal(err)
	}
	for _, chunkSize := range []uint32{1024 * 1024, 64 * 1024 * 1024} {
		name := fmt.Sprintf("Chunk_%dMiB", chunkSize/(1024*1024))
		plaintext := make([]byte, chunkSize)
		wire := encryptStream(b, key, plaintext, nil, chunkSize)
		b.Run("Encrypt_"+name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(plaintext)))
			for b.Loop() {
				if err := stream.Encrypt(bytes.NewReader(plaintext), io.Discard, nil, chunkSize); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("Decrypt_"+name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(plaintext)))
			for b.Loop() {
				if err := stream.Decrypt(bytes.NewReader(wire), io.Discard, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkAESStreamingDefaultChunkAcrossInputSizes(b *testing.B) {
	key := bytes.Repeat([]byte{0x42}, 32)
	stream, err := NewAESStreamingCrypter(key)
	if err != nil {
		b.Fatal(err)
	}
	for _, inputSize := range []int{1024 * 1024, 64 * 1024 * 1024} {
		name := fmt.Sprintf("Input_%dMiB", inputSize/(1024*1024))
		plaintext := make([]byte, inputSize)
		wire := encryptStream(b, key, plaintext, nil, DefaultAESChunkSize)
		b.Run("Encrypt_"+name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(inputSize))
			for b.Loop() {
				if err := stream.Encrypt(bytes.NewReader(plaintext), io.Discard, nil, DefaultAESChunkSize); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("Decrypt_"+name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(inputSize))
			for b.Loop() {
				if err := stream.Decrypt(bytes.NewReader(wire), io.Discard, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkAES256StreamingLargeFileInput(b *testing.B) {
	key := bytes.Repeat([]byte{0x42}, 32)
	stream, err := NewAESStreamingCrypter(key)
	if err != nil {
		b.Fatal(err)
	}
	for _, input := range []struct {
		name string
		size int64
	}{
		{name: "256MiB", size: 256 * 1024 * 1024},
		{name: "1GiB", size: 1024 * 1024 * 1024},
	} {
		b.Run(input.name, func(b *testing.B) {
			plaintextPath, ciphertextPath, ciphertextSize := prepareAESStreamingFileFixture(b, stream, input.size)

			b.Run("Encrypt_FileInput", func(b *testing.B) {
				plaintext := openBenchmarkFile(b, plaintextPath)
				defer closeBenchmarkFile(b, plaintext)
				reader := &benchmarkByteCountingReader{Reader: plaintext}
				b.ReportAllocs()
				b.SetBytes(input.size)
				// Open and close are setup costs; each iteration includes the seek and complete file read.
				for b.Loop() {
					if _, err := plaintext.Seek(0, io.SeekStart); err != nil {
						b.Fatal(err)
					}
					reader.n = 0
					if err := stream.Encrypt(reader, io.Discard, nil, DefaultAESChunkSize); err != nil {
						b.Fatal(err)
					}
					if reader.n != input.size {
						b.Fatalf("encrypted %d plaintext bytes, want %d", reader.n, input.size)
					}
				}
			})

			b.Run("Decrypt_FileInput", func(b *testing.B) {
				ciphertext := openBenchmarkFile(b, ciphertextPath)
				defer closeBenchmarkFile(b, ciphertext)
				reader := &benchmarkByteCountingReader{Reader: ciphertext}
				writer := &benchmarkByteCountingWriter{Writer: io.Discard}
				b.ReportAllocs()
				b.SetBytes(input.size)
				// Open and close are setup costs; each iteration includes the seek and complete file read.
				for b.Loop() {
					if _, err := ciphertext.Seek(0, io.SeekStart); err != nil {
						b.Fatal(err)
					}
					reader.n = 0
					writer.n = 0
					if err := stream.Decrypt(reader, writer, nil); err != nil {
						b.Fatal(err)
					}
					if reader.n != ciphertextSize {
						b.Fatalf("read %d ciphertext bytes, want %d", reader.n, ciphertextSize)
					}
					if writer.n != input.size {
						b.Fatalf("decrypted %d plaintext bytes, want %d", writer.n, input.size)
					}
				}
			})
		})
	}
}

func prepareAESStreamingFileFixture(
	b *testing.B,
	stream *AESStreamingCrypter,
	plaintextSize int64,
) (string, string, int64) {
	b.Helper()
	directory := b.TempDir()
	plaintextPath := filepath.Join(directory, "plaintext")
	ciphertextPath := filepath.Join(directory, "ciphertext")
	wantDigest := writePatternedBenchmarkFile(b, plaintextPath, plaintextSize)
	encryptAESStreamingBenchmarkFile(b, stream, plaintextPath, ciphertextPath)
	info, err := os.Stat(ciphertextPath)
	if err != nil {
		b.Fatal(err)
	}
	ciphertextSize := info.Size()
	if ciphertextSize <= plaintextSize {
		b.Fatalf("ciphertext fixture size = %d, want greater than plaintext size %d", ciphertextSize, plaintextSize)
	}
	verifyAESStreamingBenchmarkFixture(b, stream, ciphertextPath, ciphertextSize, plaintextSize, wantDigest)
	return plaintextPath, ciphertextPath, ciphertextSize
}

func writePatternedBenchmarkFile(b *testing.B, path string, size int64) [sha256.Size]byte {
	b.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		b.Fatal(err)
	}
	defer closeBenchmarkFile(b, file)
	pattern := make([]byte, 64*1024)
	for i := range pattern {
		pattern[i] = byte(i*31 + 17)
	}
	hasher := sha256.New()
	writer := io.MultiWriter(file, hasher)
	for remaining := size; remaining > 0; {
		count := min(int64(len(pattern)), remaining)
		written, err := writer.Write(pattern[:count])
		if err != nil {
			b.Fatal(err)
		}
		if int64(written) != count {
			b.Fatal(io.ErrShortWrite)
		}
		remaining -= count
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest
}

func encryptAESStreamingBenchmarkFile(
	b *testing.B,
	stream *AESStreamingCrypter,
	plaintextPath, ciphertextPath string,
) {
	b.Helper()
	plaintext := openBenchmarkFile(b, plaintextPath)
	defer closeBenchmarkFile(b, plaintext)
	ciphertext, err := os.OpenFile(ciphertextPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		b.Fatal(err)
	}
	defer closeBenchmarkFile(b, ciphertext)
	if err := stream.Encrypt(plaintext, ciphertext, nil, DefaultAESChunkSize); err != nil {
		b.Fatal(err)
	}
}

func verifyAESStreamingBenchmarkFixture(
	b *testing.B,
	stream *AESStreamingCrypter,
	ciphertextPath string,
	ciphertextSize, plaintextSize int64,
	wantDigest [sha256.Size]byte,
) {
	b.Helper()
	ciphertext := openBenchmarkFile(b, ciphertextPath)
	defer closeBenchmarkFile(b, ciphertext)
	reader := &benchmarkByteCountingReader{Reader: ciphertext}
	hasher := sha256.New()
	writer := &benchmarkByteCountingWriter{Writer: hasher}
	if err := stream.Decrypt(reader, writer, nil); err != nil {
		b.Fatal(err)
	}
	if reader.n != ciphertextSize {
		b.Fatalf("read %d ciphertext fixture bytes, want %d", reader.n, ciphertextSize)
	}
	if writer.n != plaintextSize {
		b.Fatalf("decrypted %d plaintext fixture bytes, want %d", writer.n, plaintextSize)
	}
	if !bytes.Equal(hasher.Sum(nil), wantDigest[:]) {
		b.Fatal("decrypted plaintext fixture digest mismatch")
	}
}

func openBenchmarkFile(b *testing.B, path string) *os.File {
	b.Helper()
	file, err := os.Open(path)
	if err != nil {
		b.Fatal(err)
	}
	return file
}

func closeBenchmarkFile(b *testing.B, file *os.File) {
	b.Helper()
	if err := file.Close(); err != nil {
		b.Error(err)
	}
}

type benchmarkByteCountingReader struct {
	io.Reader
	n int64
}

func (r *benchmarkByteCountingReader) Read(data []byte) (int, error) {
	n, err := r.Reader.Read(data)
	r.n += int64(n)
	return n, err //nolint:wrapcheck // Preserve source errors.
}

type benchmarkByteCountingWriter struct {
	io.Writer
	n int64
}

func (w *benchmarkByteCountingWriter) Write(data []byte) (int, error) {
	n, err := w.Writer.Write(data)
	w.n += int64(n)
	return n, err //nolint:wrapcheck // Preserve sink errors.
}
