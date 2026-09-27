package crypter

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
)

func BenchmarkAESFormatStreaming(b *testing.B) {
	key := make([]byte, 32)
	primitive, err := subtle.NewAESGCMHKDF(key, "SHA256", 32, 1<<20, 0)
	if err != nil {
		b.Fatal(err)
	}
	formats := []struct {
		encrypt func(io.Reader, io.Writer) error
		decrypt func(io.Reader, io.Writer) error
		name    string
	}{
		{
			name: "OpenPGP",
			encrypt: func(input io.Reader, output io.Writer) error {
				return EncryptOpenPGP(key, 1<<20, input, output)
			},
			decrypt: func(input io.Reader, output io.Writer) error {
				reader, err := PrepareOpenPGP(key, input)
				if err != nil {
					return err
				}
				return reader.CopyTo(output)
			},
		},
		{
			name: "Tink",
			encrypt: func(input io.Reader, output io.Writer) error {
				return EncryptTink(primitive, input, output, nil)
			},
			decrypt: func(input io.Reader, output io.Writer) error {
				reader, err := primitive.NewDecryptingReader(input, nil)
				if err != nil {
					return fmt.Errorf("open Tink reader: %w", err)
				}
				_, err = io.Copy(output, reader)
				if err != nil {
					return fmt.Errorf("read Tink plaintext: %w", err)
				}
				return nil
			},
		},
	}
	for _, format := range formats {
		for _, size := range []struct {
			name  string
			bytes int64
		}{
			{name: "1MiB", bytes: 1 << 20},
			{name: "64MiB", bytes: 64 << 20},
			{name: "256MiB", bytes: 256 << 20},
		} {
			b.Run(format.name+"/encrypt/"+size.name, func(b *testing.B) {
				b.SetBytes(size.bytes)
				b.ReportAllocs()
				for range b.N {
					input := io.LimitReader(aesZeroReader{}, size.bytes)
					if err := format.encrypt(input, io.Discard); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run(format.name+"/decrypt/"+size.name, func(b *testing.B) {
				path := filepath.Join(b.TempDir(), "ciphertext")
				output, err := os.Create(path)
				if err != nil {
					b.Fatal(err)
				}
				input := io.LimitReader(aesZeroReader{}, size.bytes)
				if err := format.encrypt(input, output); err != nil {
					b.Fatal(err)
				}
				if err := output.Close(); err != nil {
					b.Fatal(err)
				}
				b.SetBytes(size.bytes)
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					file, err := os.Open(path)
					if err != nil {
						b.Fatal(err)
					}
					if err := format.decrypt(file, io.Discard); err != nil {
						b.Fatal(errors.Join(err, file.Close()))
					}
					if err := file.Close(); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

type aesZeroReader struct{}

func (aesZeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
