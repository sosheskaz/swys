//go:build !windows

package cmd

import (
	"errors"
	"syscall"
)

func isPlatformBrokenPipe(err error) bool {
	return errors.Is(err, syscall.EPIPE)
}
