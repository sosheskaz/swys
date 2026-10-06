// Package testcmd runs command trees through their production lifecycle in tests.
package testcmd

import (
	"bytes"
	"io"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
)

// Run executes a command tree through its production stream cleanup.
func Run(tb testing.TB, root *cobra.Command, input io.Reader, output, stderr io.Writer, args ...string) error {
	tb.Helper()
	root.SetIn(input)
	root.SetOut(output)
	root.SetErr(stderr)
	root.SetArgs(args)
	return commandio.Execute(root)
}

// RunStreams captures stdout and stderr from Run.
func RunStreams(tb testing.TB, root *cobra.Command, input io.Reader, args ...string) ([]byte, []byte, error) {
	tb.Helper()
	var output, stderr bytes.Buffer
	err := Run(tb, root, input, &output, &stderr, args...)
	return output.Bytes(), stderr.Bytes(), err
}
