package cmd

import (
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/sosheskaz-systems/npc/internal/securefile"
)

func writeOwnerOnlyFixture(t *testing.T, path, contents string) {
	t.Helper()
	file, err := securefile.OpenOrCreateOwnerOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString(contents)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		t.Fatal(err)
	}
}

func assertPrivateOutput(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("output permissions = %04o, want 0600", info.Mode().Perm())
	}
	// On Windows the owner-only contract is enforced by a DACL, not mode bits.
	file, err := securefile.OpenOrCreateOwnerOnly(path)
	if err != nil {
		t.Fatalf("output does not satisfy owner-only policy: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertWindowsModeRejection(t *testing.T, err error, path, contents string) {
	t.Helper()
	if !errors.Is(err, errOutputModeUnsupported) {
		t.Fatalf("error = %v, want unsupported output mode", err)
	}
	if contents == "" {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("output stat = %v, want not-exist", err)
		}
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != contents {
		t.Fatalf("output = %q, want preserved %q", data, contents)
	}
}
