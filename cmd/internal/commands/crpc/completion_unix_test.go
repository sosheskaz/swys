//go:build unix

package crpc_test

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

func TestCRPCCompletionDoesNotOpenFIFOFiles(t *testing.T) {
	t.Parallel()
	fifo := filepath.Join(t.TempDir(), "input.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	for _, flag := range []string{"--protoset", "--ca"} {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		root := cmd.NewCommand()
		root.SetContext(ctx)
		stdout, _, err := testcmd.RunStreams(t, root, &unexpectedInput{t: t}, "__complete", "crpc", "https://example.test", flag, fifo, "example.v1.EchoService/E")
		require.NoError(t, err)
		assert.NoError(t, ctx.Err(), "completion must reject a FIFO without waiting for its deadline")
		cancel()
		assert.Equal(t, ":4\n", string(stdout))
	}
}
