//go:build linux

package grpc_test

import (
	"os"
	"strconv"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func openGRPCTestTerminal(t *testing.T) *os.File {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_CLOEXEC, 0)
	require.NoError(t, err, "open pseudo-terminal master: %v", err)
	t.Cleanup(func() {
		if err := master.Close(); err != nil {
			t.Errorf("close pseudo-terminal master: %v", err)
		}
	})

	var number uint32
	if _, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		master.Fd(),
		syscall.TIOCGPTN,
		uintptr(unsafe.Pointer(&number)),
	); errno != 0 {
		t.Fatalf("read pseudo-terminal number: %v", errno)
	}
	var unlocked int32
	if _, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		master.Fd(),
		syscall.TIOCSPTLCK,
		uintptr(unsafe.Pointer(&unlocked)),
	); errno != 0 {
		t.Fatalf("unlock pseudo-terminal: %v", errno)
	}
	slave, err := os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(number), 10), os.O_RDWR|syscall.O_NOCTTY, 0)
	require.NoError(t, err, "open pseudo-terminal slave: %v", err)
	t.Cleanup(func() {
		if err := slave.Close(); err != nil {
			t.Errorf("close pseudo-terminal slave: %v", err)
		}
	})
	return slave
}
