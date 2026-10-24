package password

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// Offsets into FreeBSD's struct kinfo_proc (sys/user.h) on LP64 targets.
const (
	freebsdKinfoPgidOffset = 80
	freebsdKinfoStatOffset = 388
	freebsdProcessStopped  = 4 // SSTOP in sys/proc.h
)

var errKinfoProcLayout = errors.New("unexpected kinfo_proc layout")

// passwordGroupStopped reports whether any process in process group pgid is stopped.
func passwordGroupStopped(pgid int) (bool, error) {
	data, err := unix.SysctlRaw("kern.proc.pgrp", pgid)
	if err != nil {
		return false, fmt.Errorf("inspect supplier process group: %w", err)
	}
	for len(data) > 0 {
		if len(data) <= freebsdKinfoStatOffset {
			return false, errKinfoProcLayout
		}
		size := int(binary.NativeEndian.Uint32(data))
		group := int(binary.NativeEndian.Uint32(data[freebsdKinfoPgidOffset:]))
		if size <= freebsdKinfoStatOffset || size > len(data) || group != pgid {
			return false, errKinfoProcLayout
		}
		if data[freebsdKinfoStatOffset] == freebsdProcessStopped {
			return true, nil
		}
		data = data[size:]
	}
	return false, nil
}
