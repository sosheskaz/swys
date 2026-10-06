// Package artifact bounds in-memory CLI artifacts and detects aliased file paths.
package artifact

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/encoding"
	"github.com/sosheskaz-systems/npc/internal/contextio"
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

// ReadEncodedSource decodes a selected file or borrowed stream before applying the decoded-byte limit.
// An exact dash selects input; other paths, including ./-, name files.
func ReadEncodedSource(ctx context.Context, input io.Reader, path string, decoder encoding.InputDecoder, limit int64) ([]byte, error) {
	if path == "-" {
		readContext, cancel := context.WithCancel(ctx)
		defer cancel()
		return Read(decoder(contextio.NewReader(readContext, input)), limit)
	}
	file, err := contextio.OpenFile(ctx, func() (*os.File, error) {
		return os.Open(path) //nolint:gosec // explicitly selected CLI artifact
	})
	if err != nil {
		return nil, fmt.Errorf("open artifact: %w", err)
	}
	owned, err := contextio.NewOwnedFileReader(ctx, file)
	if err != nil {
		return nil, fmt.Errorf("prepare artifact input: %w", err)
	}
	data, readErr := Read(decoder(owned), limit)
	if err := errors.Join(readErr, owned.Close()); err != nil {
		return nil, err
	}
	return data, nil
}
