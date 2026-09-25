package testcmd

import (
	"errors"
	"os"
	"testing"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
)

// AssertWindowsModeRejection checks that a rejected mode preserves the output fixture.
func AssertWindowsModeRejection(t *testing.T, err error, path, contents string) {
	t.Helper()
	if !errors.Is(err, commandio.ErrOutputModeUnsupported) {
		t.Fatalf("error = %v, want unsupported output mode", err)
	}
	if contents == "" {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("output stat = %v, want not-exist", err)
		}
		return
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is a test-managed output fixture
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != contents {
		t.Fatalf("output = %q, want preserved %q", data, contents)
	}
}
