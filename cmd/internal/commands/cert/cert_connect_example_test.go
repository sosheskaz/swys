package cert_test

import (
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rootcmd "github.com/sosheskaz/swys/cmd"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

func TestExampleConnectVerifiesWithPrivateCA(t *testing.T) {
	t.Parallel()
	identity := testcmd.CreateNetworkIdentity(t, rootcmd.NewCommand)
	endpoint := newIdentityTLSServer(t, &identity)

	output, diagnostics, err := executeRootStreams(t, "cert", "connect", endpoint, "--ca", identity.CACert, "-f", "json")
	require.NoError(t, err)
	verification := decodeConnectVerification(t, output)
	assert.True(t, verification.Verified, "verification error: %s", verification.Error)
	assert.Empty(t, diagnostics)

	output, _, err = executeRootStreams(t, "cert", "connect", endpoint, "--ca", identity.CACert, "--select", "root", "-f", "pem")
	require.NoError(t, err)
	assert.Equal(t, certificateFileDER(t, identity.CACert), singlePEMCertificate(t, output), "root comes from the verified chain")
}

func TestExampleConnectReportsUntrustedPrivateCAWithoutFailing(t *testing.T) {
	t.Parallel()
	identity := testcmd.CreateNetworkIdentity(t, rootcmd.NewCommand)
	endpoint := newIdentityTLSServer(t, &identity)

	output, diagnostics, err := executeRootStreams(t, "cert", "connect", endpoint, "-f", "pem")
	require.NoError(t, err, "verification is a report, not a retrieval failure")
	assert.Equal(t, certificateFileDER(t, identity.ServerCert), singlePEMCertificate(t, output))
	assert.Contains(t, diagnostics, "not verified")

	_, _, err = executeRootStreams(t, "cert", "connect", endpoint, "--select", "root", "-f", "pem")
	require.ErrorContains(t, err, "root unavailable", "the default trust store cannot discover a private root")
}

type connectVerification struct {
	Error    string `json:"error"`
	Verified bool   `json:"verified"`
}

func decodeConnectVerification(t *testing.T, output string) connectVerification {
	t.Helper()
	var report struct {
		Verification connectVerification `json:"verification"`
	}
	require.NoError(t, json.Unmarshal([]byte(output), &report))
	return report.Verification
}

func singlePEMCertificate(t *testing.T, output string) []byte {
	t.Helper()
	block, rest := pem.Decode([]byte(output))
	require.NotNil(t, block, "output is not PEM: %q", output)
	assert.Equal(t, "CERTIFICATE", block.Type)
	assert.Empty(t, rest)
	return block.Bytes
}

func certificateFileDER(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block, "%s is not PEM", path)
	return block.Bytes
}
