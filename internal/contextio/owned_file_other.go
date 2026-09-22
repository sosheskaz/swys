//go:build !darwin

package contextio

import (
	"context"
	"io"
	"os"
)

func newOwnedFilePlatformReader(
	_ context.Context,
	file *os.File,
	_ os.FileMode,
	_ <-chan struct{},
) (io.Reader, func() error, error) {
	return file, nil, nil
}
