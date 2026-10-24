//go:build freebsd || linux

package password_test

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// controlPromptPTY runs an ioctl without File.Fd, which would switch the
// master to blocking mode so that closing it no longer interrupts a reader.
func controlPromptPTY(master *os.File, ioctl func(fd int) error) error {
	conn, err := master.SyscallConn()
	if err != nil {
		return fmt.Errorf("access pseudo-terminal master: %w", err)
	}
	var ioctlErr error
	if err := conn.Control(func(fd uintptr) { ioctlErr = ioctl(int(fd)) }); err != nil {
		return fmt.Errorf("control pseudo-terminal master: %w", err)
	}
	return ioctlErr
}

func promptPTYNumber(t *testing.T, master *os.File) int {
	t.Helper()
	var number int
	err := controlPromptPTY(master, func(fd int) error {
		value, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
		if err != nil {
			return fmt.Errorf("TIOCGPTN: %w", err)
		}
		number = value
		return nil
	})
	if err != nil {
		_ = master.Close() //nolint:errcheck // the lookup failure is the reported error
		t.Fatalf("read pseudo-terminal number: %v", err)
	}
	return number
}
