package netconn

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"
)

func BenchmarkRelay(b *testing.B) {
	sizes := []int{
		1024,
		32 * 1024,
		128 * 1024,
	}
	for _, size := range sizes {
		payload := make([]byte, size)
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				client, peer := newPipeStream(b)
				peerDone := make(chan error, 1)
				go func() {
					_, readErr := io.CopyN(io.Discard, peer, int64(size))
					peerDone <- errors.Join(readErr, peer.Close())
				}()
				if err := RelayWithOptions(
					b.Context(),
					client,
					bytes.NewReader(payload),
					io.Discard,
					RelayOptions{Wait: time.Second, CloseWrite: true},
				); err != nil {
					b.Fatal(err)
				}
				if err := <-peerDone; err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
