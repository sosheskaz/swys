//go:build !windows && !darwin

package securefile

import (
	"errors"
	"fmt"
	"os"
)

// OpenOrCreateOwnerOnly opens path for writing without truncating it. A missing
// path is created owner-only; an existing regular file must already be owned by
// the effective user and grant no group or other permissions.
func OpenOrCreateOwnerOnly(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o600) //nolint:gosec // owner-only creation is the purpose of this package
	if err != nil {
		return nil, fmt.Errorf("open owner-only file: %w", err)
	}
	fail := func(err error) (*os.File, error) {
		return nil, errors.Join(err, file.Close())
	}

	if _, err := validateUnixOwnerOnly(file); err != nil {
		return fail(err)
	}
	return file, nil
}
