//go:build unix

package grpc_test

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGRPCCompletionDoesNotOpenFIFOFiles(t *testing.T) {
	t.Parallel()

	fifo := filepath.Join(t.TempDir(), "completion.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	address, _, record := startGRPCFixture(t, grpcFixtureReflectionBoth, false)
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "protoset",
			args: []string{address, "--protoset", fifo, "fixture."},
		},
		{
			name: "custom CA",
			args: []string{address, "--ca", fifo, "fixture."},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			started := time.Now()
			values, directive := completeGRPCCommand(t, test.args...)
			if len(values) != 0 {
				t.Fatalf("FIFO completion = %q, want no candidates", values)
			}
			assertGRPCCompletionDirective(t, directive)
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("FIFO completion blocked for %v", elapsed)
			}
		})
	}
	if connections := record.connectionCount(); connections != 0 {
		t.Fatalf("FIFO completion opened %d network connections, want none", connections)
	}
}
