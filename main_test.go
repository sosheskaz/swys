package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunReportsExitStatus(t *testing.T) { //nolint:paralleltest // mutates process-wide os.Args
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })

	os.Args = []string{"npc", "--version"}
	require.Equal(t, 0, run(), "exit status for a successful command")

	os.Args = []string{"npc", "no-such-command"}
	require.Equal(t, 1, run(), "exit status for a failed command")
}
