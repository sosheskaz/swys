//go:build darwin

package cmd

import (
	"os"
	"syscall"
	"testing"
	"unsafe"
)

func openGRPCTestTerminal(t *testing.T) *os.File {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open pseudo-terminal master: %v", err)
	}
	t.Cleanup(func() {
		if err := master.Close(); err != nil {
			t.Errorf("close pseudo-terminal master: %v", err)
		}
	})

	name := make([]byte, 128)
	if _, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		master.Fd(),
		syscall.TIOCPTYGNAME,
		uintptr(unsafe.Pointer(&name[0])),
	); errno != 0 {
		t.Fatalf("read pseudo-terminal slave name: %v", errno)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCPTYGRANT, 0); errno != 0 {
		t.Fatalf("grant pseudo-terminal: %v", errno)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCPTYUNLK, 0); errno != 0 {
		t.Fatalf("unlock pseudo-terminal: %v", errno)
	}
	end := 0
	for end < len(name) && name[end] != 0 {
		end++
	}
	if end == len(name) {
		t.Fatal("pseudo-terminal slave name was not NUL-terminated")
	}
	slave, err := os.OpenFile(string(name[:end]), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open pseudo-terminal slave: %v", err)
	}
	t.Cleanup(func() {
		if err := slave.Close(); err != nil {
			t.Errorf("close pseudo-terminal slave: %v", err)
		}
	})
	return slave
}
