package commandio

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/sosheskaz-systems/npc/internal/contextio"
)

// ErrSameInputOutput identifies two paths that name the same file.
var ErrSameInputOutput = errors.New("input and output refer to the same file")

// NormalizeMainStreamPath treats an exact dash as the configured stdin or stdout.
func NormalizeMainStreamPath(path string) string {
	if path == "-" {
		return ""
	}
	return path
}

// OpenInput opens a selected file without blocking context cancellation.
func OpenInput(ctx context.Context, path string) (*os.File, error) {
	return contextio.OpenFile(ctx, func() (*os.File, error) {
		file, err := os.Open(path) //nolint:gosec // explicit user-selected CLI path
		if err != nil {
			return nil, fmt.Errorf("open %q for reading: %w", path, err)
		}
		return file, nil
	})
}

// RejectSameFile prevents truncation of an input selected as output.
func RejectSameFile(inputPath, outputPath string) error {
	if inputPath == "" || outputPath == "" {
		return nil
	}
	inputInfo, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("stat input %q: %w", inputPath, err)
	}
	outputInfo, err := os.Stat(outputPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat output %q: %w", outputPath, err)
	}
	if os.SameFile(inputInfo, outputInfo) {
		return fmt.Errorf("%w: %q", ErrSameInputOutput, inputPath)
	}
	return nil
}
