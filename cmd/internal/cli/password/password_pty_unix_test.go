//go:build darwin || freebsd || linux

package password_test

import (
	"os"
	"syscall"
	"testing"
)

func openPromptPTYSlave(t *testing.T, master *os.File, name string) *os.File {
	t.Helper()
	slave, err := os.OpenFile(name, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		_ = master.Close() //nolint:errcheck // the open failure is the reported error
		t.Fatalf("open pseudo-terminal slave %s: %v", name, err)
	}
	return slave
}
