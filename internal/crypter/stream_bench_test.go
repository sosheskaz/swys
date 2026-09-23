package crypter

import (
	"bytes"
	"fmt"
	"io"
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
