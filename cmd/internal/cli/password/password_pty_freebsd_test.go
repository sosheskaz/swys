package password_test

import (
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

const promptTermiosRequest = unix.TIOCGETA

// openPromptPTY returns a pseudo-terminal master and slave; the caller closes both.
// FreeBSD has no /dev/ptmx, and its pts(4) slaves need no unlock.
func openPromptPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fd, _, errno := unix.Syscall(unix.SYS_POSIX_OPENPT, uintptr(unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC), 0, 0)
	if errno != 0 {
		t.Fatalf("open pseudo-terminal master: %v", errno)
	}
	// A nonblocking descriptor makes the File pollable, so Close interrupts readers.
	if err := unix.SetNonblock(int(fd), true); err != nil {
		_ = unix.Close(int(fd)) //nolint:errcheck // the mode failure is the reported error
		t.Fatalf("make pseudo-terminal master nonblocking: %v", err)
	}
	master := os.NewFile(fd, "/dev/ptmx")
	return master, openPromptPTYSlave(t, master, "/dev/pts/"+strconv.Itoa(promptPTYNumber(t, master)))
}
