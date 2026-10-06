package grpc_test

import (
	"bytes"
	"errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	grpccommand "github.com/sosheskaz/swys/cmd/internal/commands/grpc"
)

func newRootCmd() *cobra.Command { return cmd.NewCommand() }

type countingReader struct {
	source io.Reader
	reads  atomic.Int64
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	reader.reads.Add(1)
	return reader.source.Read(buffer) //nolint:wrapcheck // preserve the wrapped reader's stream semantics
}

var (
	errInvalidGRPCOptions  = grpccommand.ErrInvalidOptions
	errInvalidGRPCMetadata = grpccommand.ErrInvalidMetadata
	errGRPCMessageLimit    = grpccommand.ErrMessageLimit
	errSameInputOutput     = commandio.ErrSameInputOutput
)

func executeRootStreams(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	return executeRootCommandStreams(t, newRootCmd(), args...)
}

func executeRootCommandStreams(t *testing.T, root *cobra.Command, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	command, runErr := root.ExecuteC()
	err := errors.Join(runErr, commandio.Close(command))
	return stdout.String(), stderr.String(), err
}
