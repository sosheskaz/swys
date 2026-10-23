package password

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

func passwordProcessStopped(pid int) (bool, error) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		if errors.Is(unix.Kill(pid, 0), unix.ESRCH) {
			return false, nil
		}
		return false, fmt.Errorf("inspect supplier process: %w", err)
	}
	return info.Proc.P_stat == darwinProcessStopped, nil
}
