package testcmd

import (
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/sosheskaz/swys/internal/securefile"
)

// AssertPrivateOutput checks file mode and the securefile owner-only policy.
func AssertPrivateOutput(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("output permissions = %04o, want 0600", info.Mode().Perm())
	}
	file, err := securefile.OpenOrCreateOwnerOnly(path)
	if err != nil {
		t.Fatalf("output does not satisfy owner-only policy: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

// WriteOwnerOnlyFixture creates or replaces path with contents under the
// securefile owner-only policy, so sensitive outputs accept it on every platform.
func WriteOwnerOnlyFixture(t *testing.T, path, contents string) {
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
