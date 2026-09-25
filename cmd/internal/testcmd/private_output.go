package testcmd

import (
	"os"
	"runtime"
	"testing"

	"github.com/sosheskaz-systems/npc/internal/securefile"
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
