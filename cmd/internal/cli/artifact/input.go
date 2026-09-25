// Package artifact bounds in-memory CLI artifacts and detects aliased file paths.
package artifact

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Artifact limits bound key and certificate parsing before output is opened.
const (
	MaxKeyBytes         int64 = 1 << 20
	MaxCertificateBytes int64 = 16 << 20
	MaxAESKeyBytes      int64 = 32
)

// ErrTooLarge identifies an artifact rejected before parsing for exceeding its limit.
var ErrTooLarge = errors.New("artifact exceeds size limit")

// Read consumes at most limit+1 bytes and rejects oversized input without returning partial data.
func Read(input io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(input, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read artifact: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w (%d bytes)", ErrTooLarge, limit)
	}
	return data, nil
}

// ReadFile applies Read's bound and closes the file, preserving read and close errors.
func ReadFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path) //nolint:gosec // reading an explicitly selected CLI artifact is intended
	if err != nil {
		return nil, fmt.Errorf("open artifact: %w", err)
	}
	data, readErr := Read(file, limit)
	if err := errors.Join(readErr, file.Close()); err != nil {
		return nil, err
	}
	return data, nil
}
