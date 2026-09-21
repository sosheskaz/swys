//go:build !darwin

package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
)

func readGRPCOwnedInput(_ context.Context, file *os.File, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, limit))
	if err != nil {
		return nil, fmt.Errorf("read gRPC input: %w", err)
	}
	return data, nil
}
