package password_test

import (
	"bytes"
	"os"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

const promptTermiosRequest = unix.TIOCGETA

// openPromptPTY returns a pseudo-terminal master and slave; the caller closes both.
func openPromptPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master := openPromptPTMX(t)
	name := make([]byte, 128)
	for _, request := range []uintptr{syscall.TIOCPTYGNAME, syscall.TIOCPTYGRANT, syscall.TIOCPTYUNLK} {
		argument := uintptr(0)
		if request == syscall.TIOCPTYGNAME {
			argument = uintptr(unsafe.Pointer(&name[0]))
		}
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), request, argument); errno != 0 {
			_ = master.Close() //nolint:errcheck // the ioctl failure is the reported error
			t.Fatalf("prepare pseudo-terminal: %v", errno)
		}
	}
	end := bytes.IndexByte(name, 0)
	if end <= 0 {
		_ = master.Close() //nolint:errcheck // the missing name is the reported error
		t.Fatal("pseudo-terminal slave name was empty or not NUL-terminated")
	}
	return master, openPromptPTYSlave(t, master, string(name[:end]))
}
