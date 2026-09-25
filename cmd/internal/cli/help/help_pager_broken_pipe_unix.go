//go:build !windows

package help

import (
	"errors"
	"syscall"
)

func isPlatformBrokenPipe(err error) bool {
	return errors.Is(err, syscall.EPIPE)
}
