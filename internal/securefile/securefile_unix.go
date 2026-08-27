//go:build !windows

package securefile

import (
	"fmt"
	"os"
	"syscall"
)

func validateUnixOwnerOnly(file *os.File) (bool, error) {
	info, err := file.Stat()
	if err != nil {
		return false, fmt.Errorf("inspect owner-only file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	if info.Mode().Perm()&0o077 != 0 {
		return true, fmt.Errorf("%w: group or other permissions are set", ErrNotOwnerOnly)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true, fmt.Errorf("%w: cannot determine file owner", ErrNotOwnerOnly)
	}
	if int(stat.Uid) != os.Geteuid() {
		return true, fmt.Errorf("%w: file is not owned by the effective user", ErrNotOwnerOnly)
	}
	return true, nil
}
