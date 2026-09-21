//go:build unix

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A FIFO without a peer blocks open(2) before any cancellation-aware I/O runs.
func TestInterruptStopsCommandBlockedOpeningAFIFO(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		signal  os.Signal
		name    string
		flag    string
		message string
		code    int
	}{
		{name: "input", flag: "--input", signal: os.Interrupt, message: "interrupted", code: 130},
		{name: "output", flag: "--output", signal: syscall.SIGTERM, message: "terminated", code: 143},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fifo := makePeerlessFIFO(t)
			run := startInterruptibleCommand(t, strings.NewReader(""), "hash", "sha256", test.flag, fifo)
			// Favor a signal that lands while the open is blocked.
			time.Sleep(100 * time.Millisecond)

			run.signals <- test.signal

			requireInterrupted(t, waitForInterruptedRun(t, run.done), test.message, test.code)
		})
	}
}

func TestInterruptStopsHTTPRequestBlockedOpeningAFIFOBody(t *testing.T) {
	t.Parallel()
	fifo := makePeerlessFIFO(t)
	run := startInterruptibleCommand(t, strings.NewReader(""), "http", "-X", "POST", "--input", fifo, "http://127.0.0.1:1")
	// Favor a signal that lands while the open is blocked.
	time.Sleep(100 * time.Millisecond)

	run.signals <- os.Interrupt

	requireInterrupted(t, waitForInterruptedRun(t, run.done), "interrupted", 130)
}

func makePeerlessFIFO(t *testing.T) string {
	t.Helper()
	fifo := filepath.Join(t.TempDir(), "peerless")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	// Give the abandoned open the peer it waits for so nothing outlives the test.
	t.Cleanup(func() {
		if peer, err := os.OpenFile(fifo, os.O_RDWR, 0); err == nil {
			_ = peer.Close() //nolint:errcheck // test cleanup is best effort
		}
	})
	return fifo
}
