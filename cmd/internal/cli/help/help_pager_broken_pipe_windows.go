//go:build windows

package help

import (
	"errors"

	"golang.org/x/sys/windows"
)

func isPlatformBrokenPipe(err error) bool {
	return errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_NO_DATA)
}
