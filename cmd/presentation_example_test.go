package cmd

import (
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExamplePlainAndStyledReports(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	aesKey, key, cert := filepath.Join(dir, "aes.key"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "cert.pem")
	_, err := executeRoot(t, "aes", "keygen", "-o", aesKey)
	require.NoError(t, err)
	_, err = executeRoot(t, "cert", "keygen", "-o", key)
	require.NoError(t, err)
	_, err = executeRoot(t, "cert", "create", "--key", key, "--subject", "CN=example.test", "-o", cert)
	require.NoError(t, err)
	for _, args := range [][]string{
		{"aes", "key-inspect", "-i", aesKey},
		{"cert", "key-inspect", "-i", key},
		{"cert", "inspect", "-i", cert},
		{"cert", "verify", "-i", cert, "--ca", cert},
		{"cert", "match", "--cert", cert, "--key", key},
	} {
		t.Run(args[0]+"/"+args[1], func(t *testing.T) {
			t.Parallel()
			plain, err := executeRoot(t, append(append([]string{}, args...), "--format", "plain")...)
			require.NoError(t, err)
			assert.NotContains(t, plain, "\x1b")
			text, err := executeRoot(t, append(append([]string{}, args...), "--format", "text")...)
			require.NoError(t, err)
			assert.Equal(t, plain, text)
			rich, err := executeRoot(t, append(append([]string{}, args...), "--style", "rich")...)
			require.NoError(t, err)
			assert.Contains(t, rich, "\x1b[")
			assert.Equal(t, plain, regexp.MustCompile(`\x1b\[[0-9;]*m`).ReplaceAllString(rich, ""))
			forcedPlain, err := executeRoot(t, append(append([]string{}, args...), "--style", "rich", "--format", "plain")...)
			require.NoError(t, err)
			assert.Equal(t, plain, forcedPlain)
		})
	}
}
