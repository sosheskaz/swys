package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	maxKeyArtifactBytes         int64 = 1 << 20
	maxCertificateArtifactBytes int64 = 16 << 20
	maxAESKeyBytes              int64 = 32
)

var errArtifactTooLarge = errors.New("artifact exceeds size limit")

func readArtifact(input io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(input, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read artifact: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w (%d bytes)", errArtifactTooLarge, limit)
	}
	return data, nil
}

func readArtifactFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path) //nolint:gosec // reading an explicitly selected CLI artifact is intended
	if err != nil {
		return nil, fmt.Errorf("open artifact: %w", err)
	}
	data, readErr := readArtifact(file, limit)
	if err := errors.Join(readErr, file.Close()); err != nil {
		return nil, err
	}
	return data, nil
}
