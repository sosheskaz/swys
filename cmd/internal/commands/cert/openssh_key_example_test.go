package cert_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/sosheskaz/swys/internal/asym"
)

func TestExampleKeyCommandsConsumeOpenSSHKeys(t *testing.T) {
	t.Parallel()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	privateBlock, err := ssh.MarshalPrivateKey(privateKey, "developer@example")
	require.NoError(t, err)
	privateData := pem.EncodeToMemory(privateBlock)

	inspection, stderr, err := executeRootStreamsWithInput(t, bytes.NewReader(privateData), "cert", "key-inspect")
	require.NoError(t, err)
	assert.Empty(t, stderr, "inspection stderr")
	assert.Contains(t, inspection, "ed25519", "inspection output")
	assert.Contains(t, inspection, "private", "inspection output")

	publicPEM, _, err := executeRootStreamsWithInput(t, bytes.NewReader(privateData), "cert", "key-public")
	require.NoError(t, err)
	public, err := asym.ParseKey([]byte(publicPEM))
	require.NoError(t, err)
	assert.False(t, public.IsPrivate(), "public output contains private key")

	sshPublic, err := ssh.NewPublicKey(privateKey.Public())
	require.NoError(t, err)
	authorizedKey := append([]byte("\n# workstation key\nrestrict,no-agent-forwarding "), bytes.TrimSpace(ssh.MarshalAuthorizedKey(sshPublic))...)
	authorizedKey = append(authorizedKey, []byte(" developer@example\n")...)
	convertedPEM, _, err := executeRootStreamsWithInput(
		t, bytes.NewReader(authorizedKey), "cert", "key-convert", "--to", "pkix-pem",
	)
	require.NoError(t, err)
	converted, err := asym.ParseKey([]byte(convertedPEM))
	require.NoError(t, err)
	assert.False(t, converted.IsPrivate(), "converted public key contains private material")
}
