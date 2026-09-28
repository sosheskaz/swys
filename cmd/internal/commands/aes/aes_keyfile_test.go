package aes_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	aescommand "github.com/sosheskaz-systems/npc/cmd/internal/commands/aes"
)

func TestAESRejectsKeyfileOutputCollisions(t *testing.T) { //nolint:paralleltest // literal-dash cases change the process working directory
	for _, leaf := range []string{"encrypt", "decrypt"} { //nolint:paralleltest // literal-dash subtests call t.Chdir
		for _, alias := range []string{"same path", "symlink", "hard link", "literal dash"} {
			t.Run(leaf+"/"+alias, func(t *testing.T) {
				dir := t.TempDir()
				keyfile := filepath.Join(dir, "key")
				if alias == "literal dash" {
					t.Chdir(dir)
					keyfile = "-"
				}
				key := bytes.Repeat([]byte{0x42}, 32)
				require.NoError(t, os.WriteFile(keyfile, key, 0o600))
				output := keyfile
				switch alias {
				case "symlink":
					output = filepath.Join(dir, "alias")
					if err := os.Symlink(keyfile, output); err != nil {
						if runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(1314)) { // ERROR_PRIVILEGE_NOT_HELD
							t.Skipf("symlink creation requires privileges: %v", err)
						}
						require.NoError(t, err, "create symlink")
					}
				case "hard link":
					output = filepath.Join(dir, "alias")
					require.NoError(t, os.Link(keyfile, output), "create hard link")
				}
				_, err := executeRoot(t, "aes", leaf, "payload", "--keyfile", keyfile, "--output", output)
				if err == nil {
					t.Error("expected keyfile/output collision error")
				}
				got, readErr := os.ReadFile(keyfile)
				require.NoError(t, readErr)
				assert.Equal(t, key, got, "keyfile changed")
				if err != nil && !errors.Is(err, aescommand.ErrAESKeyOutputCollision) {
					t.Errorf("error = %v, want keyfile/output collision", err)
				}
			})
		}
	}
}

func TestAESKeyfileRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyfile := filepath.Join(dir, "key")
	encrypted := filepath.Join(dir, "encrypted")
	require.NoError(t, os.WriteFile(keyfile, bytes.Repeat([]byte{0x42}, 32), 0o600))
	_, err := executeRoot(t, "aes", "encrypt", "hello", "--keyfile", keyfile, "--output", encrypted)
	require.NoError(t, err)
	got, err := executeRoot(t, "aes", "decrypt", "--keyfile", keyfile, "--input", encrypted)
	require.NoError(t, err)
	assert.Equal(t, "hello", got)
}

func TestAESKeyfilePathErrorPreservesOutput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	parent := filepath.Join(dir, "parent")
	require.NoError(t, os.WriteFile(parent, nil, 0o600))
	keyfile := filepath.Join(parent, "key")
	output := filepath.Join(dir, "output")
	original := []byte("preserve")
	require.NoError(t, os.WriteFile(output, original, 0o600))
	_, err := executeRoot(t, "aes", "encrypt", "hello", "--keyfile", keyfile, "--output", output)
	require.ErrorIs(t, err, syscall.ENOTDIR, "error = %v, want source path error", err)
	got, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.Equal(t, original, got, "output changed")
}
