//go:build !windows

package cmd

import (
	"errors"
	"fmt"
	"os"
)

func openExclusivePrivateKey(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // private key is created with owner-only permissions
	if err != nil {
		return nil, fmt.Errorf("open private key file: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		closeErr := file.Close()
		removeErr := os.Remove(path)
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		return nil, errors.Join(fmt.Errorf("set owner-only permissions: %w", err), closeErr, removeErr)
	}
	return file, nil
}
