//go:build darwin || freebsd || linux

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

func openPromptPTYSlave(t *testing.T, master *os.File, name string) *os.File {
	t.Helper()
	slave, err := os.OpenFile(name, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		_ = master.Close() //nolint:errcheck // the open failure is the reported error
		t.Fatalf("open pseudo-terminal slave %s: %v", name, err)
	}
	return slave
}
