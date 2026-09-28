package cmd

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateInspectEscapesCommonName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	certPath := filepath.Join(dir, "cert.pem")
	_, err := executeRoot(t, "cert", "keygen", "--output", keyPath)
	require.NoError(t, err)
	_, err = executeRoot(t, "cert", "create", "--key", keyPath, "--subject", "CN=demo\x1b[2J", "--output", certPath)
	require.NoError(t, err)
	for _, format := range []string{"text", "long"} {
		output, err := executeRoot(t, "cert", "inspect", "--input", certPath, "--format", format)
		require.NoError(t, err)
		assert.NotContains(t, output, "\x1b", "unsafe certificate output")
		assert.Contains(t, output, `demo\x1b[2J`, "escaped common name")
	}
}
