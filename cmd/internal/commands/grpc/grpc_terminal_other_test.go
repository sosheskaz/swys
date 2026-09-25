//go:build !darwin && !linux

package grpc_test

import (
	"os"
	"testing"
)

func openGRPCTestTerminal(t *testing.T) *os.File {
	t.Helper()
	t.Skip("native pseudo-terminal fixture is currently available on Darwin and Linux")
	return nil
}
