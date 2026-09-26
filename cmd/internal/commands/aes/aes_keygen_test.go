package aes_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAESKeygenBits(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		args  []string
		bytes int
	}{
		{name: "default 256", bytes: 32},
		{name: "explicit 128", args: []string{"--bits", "128"}, bytes: 16},
		{name: "explicit 256", args: []string{"-b", "256"}, bytes: 32},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := append([]string{"aes", "keygen"}, test.args...)
			output, stderr, err := executeRootStreams(t, args...)
			require.NoError(t, err)
			require.Empty(t, stderr)
			require.Len(t, []byte(output), test.bytes)
		})
	}
}

func TestAESKeygenRejectsInvalidSelectionsBeforeOutput(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"aes", "keygen", "--bits", "192"},
		{"aes", "keygen", "unexpected"},
	} {
		path := filepath.Join(t.TempDir(), "existing.key")
		require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
		_, _, err := executeRootStreams(t, append(args, "--output", path)...)
		require.Error(t, err, "args %v", args)
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, []byte("preserve"), data)
	}
}
