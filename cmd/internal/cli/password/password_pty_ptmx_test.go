//go:build darwin || linux

package password_test

import (
	"os"
	"syscall"
	"testing"
)

func openPromptPTMX(t *testing.T) *os.File {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open pseudo-terminal master: %v", err)
	}
	return master
}
