//go:build !darwin && !freebsd && !linux && !windows

package password

import "errors"

func passwordProcessStopped(int) (bool, error) {
	return false, errors.New("interactive password commands are unsupported on this operating system")
}
