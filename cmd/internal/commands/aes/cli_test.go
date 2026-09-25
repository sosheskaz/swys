package aes_test

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	rootcmd "github.com/sosheskaz-systems/npc/cmd"
	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
)

const testAESStreamHeaderSize = 16

func newAESLeaf(t *testing.T, name string) *cobra.Command {
	t.Helper()
	command, _, err := rootcmd.NewCommand().Find([]string{"aes", name})
	require.NoError(t, err)
	require.Equal(t, name, command.Name())
	return command
}

func executeRootStreams(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	stdout, stderr, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, args...)
	return string(stdout), string(stderr), err
}

func executeRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	stdout, stderr, err := executeRootStreams(t, args...)
	return stdout + stderr, err
}
