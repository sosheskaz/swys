//go:build freebsd || linux

package password_test

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func promptPTYNumber(t *testing.T, master *os.File) int {
	t.Helper()
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		_ = master.Close() //nolint:errcheck // the lookup failure is the reported error
		t.Fatalf("read pseudo-terminal number: %v", err)
	}
	return number
}
