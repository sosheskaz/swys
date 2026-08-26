//go:build !windows

package cmd

import (
	"os"
	"testing"
)

func assertPrivateKeyProtection(t *testing.T, path string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %04o, want 0600", info.Mode().Perm())
	}
}
