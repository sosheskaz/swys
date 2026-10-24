package password

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func passwordProcessStopped(pid int) (bool, error) {
	var status syscall.WaitStatus
	// wait6 keeps this status waitable for exec.Cmd.Wait. FreeBSD P_PID is 0;
	// x/sys/unix has no wait6 wrapper. See https://man.freebsd.org/cgi/man.cgi?query=wait6&sektion=2
	observed, _, errno := syscall.Syscall6(syscall.SYS_WAIT6, 0, uintptr(pid), uintptr(unsafe.Pointer(&status)),
		uintptr(unix.WSTOPPED|unix.WNOWAIT|unix.WNOHANG), 0, 0)
	if errors.Is(errno, unix.ECHILD) || errors.Is(errno, unix.ESRCH) {
		return false, nil
	}
	if errno != 0 {
		return false, fmt.Errorf("inspect supplier process: %w", errno)
	}
	// Go's BSD WaitStatus.Stopped reports a SIGSTOP stop as a continuation. FreeBSD
	// reports continuation only for WCONTINUED, which this probe does not request,
	// so any _WSTOPPED status is a stop.
	return observed == uintptr(pid) && status&freebsdWaitStatusMask == freebsdWaitStopped, nil
}

// freebsdWaitStopped is _WSTOPPED from <sys/wait.h>.
const (
	freebsdWaitStatusMask = 0o177
	freebsdWaitStopped    = 0o177
)
