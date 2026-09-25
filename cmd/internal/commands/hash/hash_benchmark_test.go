package hash_test

import (
	"fmt"
	"io"
	"testing"
)

func BenchmarkHashStreaming(b *testing.B) {
	for _, size := range []int64{4 << 10, 1 << 20, 64 << 20} {
		b.Run(hashBenchmarkSize(size), func(b *testing.B) {
			b.SetBytes(size)
			b.ReportAllocs()
			for b.Loop() {
				input := io.LimitReader(hashBenchmarkReader{}, size)
				if err := runHashCommand(b, input, io.Discard, "hash", "sha256", "--encoding", "raw"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func hashBenchmarkSize(size int64) string {
	if size >= 1<<20 {
		return fmt.Sprintf("%dMiB", size>>20)
	}
	return fmt.Sprintf("%dKiB", size>>10)
}

type hashBenchmarkReader struct{}

func (hashBenchmarkReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = byte(index*31 + 17)
	}
	return len(buffer), nil
}
