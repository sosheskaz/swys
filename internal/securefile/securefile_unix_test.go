//go:build !windows

package securefile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpenOrCreateOwnerOnlyRejectsInsecureExistingFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "private.key")
	if err := os.WriteFile(path, []byte("preserve"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenOrCreateOwnerOnly(path); !errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("open error = %v, want ErrNotOwnerOnly", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "preserve" {
		t.Fatalf("contents = %q, want preserved", data)
	}
}

func TestOpenOrCreateOwnerOnlyPreservesSecureExistingModeAndContents(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "private.key")
	if err := os.WriteFile(path, []byte("preserve"), 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := OpenOrCreateOwnerOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "preserve" {
		t.Fatalf("contents = %q, want preserved", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("mode = %04o, want preserved 0700", got)
	}
}

func TestOpenOrCreateOwnerOnlyHandlesDanglingSymlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("create symlink: %v", err)
	}
	file, err := OpenOrCreateOwnerOnly(link)
	if runtime.GOOS == "darwin" {
		if err == nil {
			if closeErr := file.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			t.Fatal("open succeeded, want dangling symlink rejection")
		}
		if _, statErr := os.Stat(target); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("target stat error = %v, want ErrNotExist", statErr)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("mode = %04o, want owner-only", info.Mode().Perm())
	}
}
