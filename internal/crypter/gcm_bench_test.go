package crypter

import (
	"bytes"
	"crypto/aes"
	"io"
	"testing"
)

func BenchmarkAESModes(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{name: "1KB", size: 1024},
		{name: "64KB", size: 64 * 1024},
		{name: "1MB", size: 1024 * 1024},
		{name: "64MB", size: 64 * 1024 * 1024},
	}
	for _, size := range sizes {
		plaintext := make([]byte, size.size)
		b.Run(size.name, func(b *testing.B) {
			benchmarkCBCMode(b, plaintext)
			benchmarkGCMMode(b, plaintext)
		})
	}
}

func benchmarkCBCMode(b *testing.B, plaintext []byte) {
	b.Helper()

	crypter := newBenchmarkCrypter(b)
	iv := make([]byte, aes.BlockSize)
	var sealed bytes.Buffer
	if err := crypter.Encrypt(iv, bytes.NewReader(plaintext), &sealed); err != nil {
		b.Fatal(err)
	}
	wire := bytes.Clone(sealed.Bytes())

	for _, operation := range []struct {
		run  func() error
		name string
	}{
		{name: "Encrypt", run: func() error {
			return crypter.Encrypt(iv, bytes.NewReader(plaintext), io.Discard)
		}},
		{name: "Decrypt", run: func() error {
			return crypter.Decrypt(bytes.NewReader(wire), io.Discard)
		}},
		{name: "RoundTrip", run: func() error {
			var output bytes.Buffer
			output.Grow(len(wire))
			if err := crypter.Encrypt(iv, bytes.NewReader(plaintext), &output); err != nil {
				return err
			}
			return crypter.Decrypt(bytes.NewReader(output.Bytes()), io.Discard)
		}},
	} {
		b.Run("CBC/"+operation.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(plaintext)))
			for b.Loop() {
				if err := operation.run(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchmarkGCMMode(b *testing.B, plaintext []byte) {
	b.Helper()

	crypter, err := NewAESGCMCrypter(make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}
	var sealed bytes.Buffer
	if err := crypter.Encrypt(bytes.NewReader(plaintext), &sealed, nil); err != nil {
		b.Fatal(err)
	}
	wire := bytes.Clone(sealed.Bytes())

	for _, operation := range []struct {
		run  func() error
		name string
	}{
		{name: "Encrypt", run: func() error {
			return crypter.Encrypt(bytes.NewReader(plaintext), io.Discard, nil)
		}},
		{name: "Decrypt", run: func() error {
			return crypter.Decrypt(bytes.NewReader(wire), io.Discard, nil)
		}},
		{name: "RoundTrip", run: func() error {
			var output bytes.Buffer
			output.Grow(len(wire))
			if err := crypter.Encrypt(bytes.NewReader(plaintext), &output, nil); err != nil {
				return err
			}
			return crypter.Decrypt(bytes.NewReader(output.Bytes()), io.Discard, nil)
		}},
	} {
		b.Run("GCM/"+operation.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(plaintext)))
			for b.Loop() {
				if err := operation.run(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
