package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/tlsconfig"
)

func TestExampleCertificateAndTLSConsumersAcceptOpenSSHPrivateKey(t *testing.T) {
	t.Parallel()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	privateBlock, err := ssh.MarshalPrivateKey(privateKey, "tls identity")
	require.NoError(t, err)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "identity.key")
	certPath := filepath.Join(dir, "identity.crt")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(privateBlock), 0o600))
	_, _, err = executeRootStreams(t, "cert", "create", "--key", keyPath, "--output", certPath)
	require.NoError(t, err)

	tlsCommand, _, err := newRootCmd().Find([]string{"net", "connect"})
	require.NoError(t, err)
	require.NotNil(t, tlsCommand)
	require.NoError(t, tlsCommand.Flags().Set(tlsconfig.CertFlagName, certPath))
	require.NoError(t, tlsCommand.Flags().Set(tlsconfig.KeyFlagName, keyPath))
	identity, configured, err := tlsconfig.ClientIdentityFromCommand(tlsCommand)
	require.NoError(t, err)
	assert.True(t, configured, "TLS identity not configured")
	assert.Len(t, identity.Certificate, 1, "TLS identity chain")
	assert.NotNil(t, identity.PrivateKey, "TLS identity private key")
}
