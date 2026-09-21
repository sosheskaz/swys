package main

import (
	"os"
	"testing"
)

func TestRunReportsExitStatus(t *testing.T) { //nolint:paralleltest // mutates process-wide os.Args
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })

	os.Args = []string{"npc", "--version"}
	if got := run(); got != 0 {
		t.Fatalf("exit status for a successful command = %d, want 0", got)
	}

	os.Args = []string{"npc", "no-such-command"}
	if got := run(); got != 1 {
		t.Fatalf("exit status for a failed command = %d, want 1", got)
	}
}
