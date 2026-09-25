package key_test

import (
	"io"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	rootcmd "github.com/sosheskaz-systems/npc/cmd"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/commands/key"
	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
)

var (
	errKeyOutputCollision         = key.ErrKeyOutputCollision
	errOutputModeUnsupported      = commandio.ErrOutputModeUnsupported
	errUnknownKeyAlgorithm        = key.ErrUnknownKeyAlgorithm
	errUnknownKeyConversionTarget = key.ErrUnknownKeyConversionTarget
	errUnknownKeyFormat           = key.ErrUnknownKeyFormat
)

func newRootCmd() *cobra.Command { return rootcmd.NewCommand() }

func keyLeaf(t *testing.T, name string) *cobra.Command {
	t.Helper()
	command, _, err := rootcmd.NewCommand().Find([]string{"key", name})
	require.NoError(t, err)
	require.Equal(t, name, command.Name())
	return command
}

func keyCommand(t *testing.T) *cobra.Command {
	t.Helper()
	command, _, err := rootcmd.NewCommand().Find([]string{"key"})
	require.NoError(t, err)
	require.Equal(t, "key", command.Name())
	return command
}

func executeRootStreams(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	stdout, stderr, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, args...)
	return string(stdout), string(stderr), err
}

func executeRootStreamsWithInput(t *testing.T, input io.Reader, args ...string) (string, string, error) {
	t.Helper()
	stdout, stderr, err := testcmd.RunStreams(t, rootcmd.NewCommand(), input, args...)
	return string(stdout), string(stderr), err
}

//nolint:unparam // Keep the root execution contract available to command tests.
func executeRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	stdout, stderr, err := executeRootStreams(t, args...)
	return stdout + stderr, err
}

func executeCommand(root *cobra.Command) error { return commandio.Execute(root) }
