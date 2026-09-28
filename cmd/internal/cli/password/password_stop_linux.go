package password

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func passwordProcessStopped(pid int) (bool, error) {
	var info unix.Siginfo
	err := unix.Waitid(unix.P_PID, pid, &info, unix.WSTOPPED|unix.WNOWAIT|unix.WNOHANG, nil)
	if errors.Is(err, unix.ECHILD) || errors.Is(err, unix.ESRCH) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect supplier process: %w", err)
	}
	return info.Signo == int32(syscall.SIGCHLD), nil
}
