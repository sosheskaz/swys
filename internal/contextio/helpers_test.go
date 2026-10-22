package contextio

import (
	"errors"
	"os"
	"testing"
	"time"
)

var errCause = errors.New("test cancellation cause")

func waitForSignal(t *testing.T, signal <-chan struct{}, failure string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(10 * time.Second):
		t.Fatal(failure)
	}
}

func waitUntil(t *testing.T, condition func() bool, failure string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(failure)
}

// fileClosed reports whether file has been closed. Stat cannot tell: on
// Windows it reads the handle without taking a reference, so after Close it
// fails with an invalid-handle error rather than os.ErrClosed, and polling it
// races Close.
func fileClosed(file *os.File) bool {
	conn, err := file.SyscallConn()
	return err == nil && conn.Control(func(uintptr) {}) != nil
}
