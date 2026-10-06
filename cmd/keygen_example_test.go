package cmd_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	rootcmd "github.com/sosheskaz/swys/cmd"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

func TestExampleCertKeygenCreatesCertificate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "identity.pem")
	certPath := filepath.Join(dir, "identity.crt")
	_, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, "cert", "keygen", "--output", keyPath)
	require.NoError(t, err)
	_, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), nil, "cert", "create", "-k", keyPath, "--dns", "localhost", "--output", certPath)
	require.NoError(t, err)
	output, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, "cert", "inspect", "--input", certPath)
	require.NoError(t, err)
	require.Contains(t, string(output), "localhost")
}

func TestExampleAESKeygenEncryptsAndDecrypts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "aes.key")
	cipherPath := filepath.Join(dir, "message.gcm")
	_, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, "aes", "keygen", "--output", keyPath)
	require.NoError(t, err)
	key, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	require.Len(t, key, 32)
	_, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader([]byte("secret message")),
		"aes", "encrypt", "--key", keyPath, "--output", cipherPath)
	require.NoError(t, err)
	plaintext, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, "aes", "decrypt", "--key", keyPath, "--input", cipherPath)
	require.NoError(t, err)
	require.Equal(t, []byte("secret message"), plaintext)
}
