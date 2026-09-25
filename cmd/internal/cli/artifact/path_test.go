package artifact

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSamePathExistingAndMissingPaths(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	missing := filepath.Join(dir, "missing")
	require.NoError(t, os.WriteFile(first, []byte("first"), 0o600))
	require.NoError(t, os.WriteFile(second, []byte("second"), 0o600))

	for _, test := range []struct {
		name  string
		left  string
		right string
	}{
		{name: "distinct existing files", left: first, right: second},
		{name: "one missing file", left: first, right: missing},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			same, err := SamePath(test.left, test.right)
			require.NoError(t, err)
			assert.False(t, same)
		})
	}

	t.Run("missing files beneath alias parents", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation requires privileges on some Windows configurations")
		}
		realParent := filepath.Join(dir, "real")
		require.NoError(t, os.Mkdir(realParent, 0o700))
		aliasParent := filepath.Join(dir, "alias")
		require.NoError(t, os.Symlink(realParent, aliasParent))
		same, err := SamePath(filepath.Join(realParent, "new"), filepath.Join(aliasParent, "new"))
		require.NoError(t, err)
		assert.True(t, same)
	})
}

func TestSamePathPreservesRawSymlinkTraversal(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("raw symlink and parent traversal is platform-specific")
	}
	dir := t.TempDir()
	realParent := filepath.Join(dir, "real")
	require.NoError(t, os.MkdirAll(filepath.Join(realParent, "child"), 0o700))
	actual := filepath.Join(realParent, "target")
	lexical := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(actual, []byte("actual"), 0o600))
	require.NoError(t, os.WriteFile(lexical, []byte("lexical"), 0o600))
	require.NoError(t, os.Symlink(filepath.Join(realParent, "child"), filepath.Join(dir, "link")))
	raw := strings.Join([]string{dir, "link", "..", "target"}, string(os.PathSeparator))
	rawInfo, err := os.Stat(raw)
	require.NoError(t, err)
	actualInfo, err := os.Stat(actual)
	require.NoError(t, err)
	lexicalInfo, err := os.Stat(lexical)
	require.NoError(t, err)
	require.True(t, os.SameFile(rawInfo, actualInfo), "fixture must traverse the symlink before ..")
	require.False(t, os.SameFile(rawInfo, lexicalInfo), "fixture must differ from the cleaned path")

	same, err := SamePath(raw, lexical)
	require.NoError(t, err)
	assert.False(t, same, "distinct existing files must not alias after lexical cleaning")
}

func TestSamePathPropagatesInspectionError(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("self-referential symlink errors are platform-specific")
	}
	dir := t.TempDir()
	loop := filepath.Join(dir, "loop")
	require.NoError(t, os.Symlink("loop", loop))
	same, err := SamePath(loop, filepath.Join(dir, "other"))
	assert.False(t, same)
	require.ErrorIs(t, err, syscall.ELOOP)
	assert.ErrorContains(t, err, loop)
}
