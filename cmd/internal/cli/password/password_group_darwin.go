package password

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// darwinProcessStopped is SSTOP in Darwin's sys/proc.h.
const darwinProcessStopped = 4

// passwordGroupStopped reports whether any process in process group pgid is stopped.
func passwordGroupStopped(pgid int) (bool, error) {
	processes, err := unix.SysctlKinfoProcSlice("kern.proc.pgrp", pgid)
	if err != nil {
		return false, fmt.Errorf("inspect supplier process group: %w", err)
	}
	for i := range processes {
		if processes[i].Proc.P_stat == darwinProcessStopped {
			return true, nil
		}
	}
	return false, nil
}
