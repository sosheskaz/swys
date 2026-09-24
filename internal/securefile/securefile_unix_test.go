//go:build !windows

package securefile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenOrCreateOwnerOnlyRejectsInsecureExistingFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "private.key")
	require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o644))
	_, err := OpenOrCreateOwnerOnly(path)
	require.ErrorIs(t, err, ErrNotOwnerOnly)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "preserve", string(data))
}

func TestOpenOrCreateOwnerOnlyPreservesSecureExistingModeAndContents(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "private.key")
	require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o700))
	file, err := OpenOrCreateOwnerOnly(path)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "preserve", string(data))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
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
		_, statErr := os.Stat(target)
		assert.ErrorIs(t, statErr, os.ErrNotExist)
		return
	}
	require.NoError(t, err)
	require.NoError(t, file.Close())
	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Zero(t, info.Mode().Perm()&0o077, "mode = %04o, want owner-only", info.Mode().Perm())
}
