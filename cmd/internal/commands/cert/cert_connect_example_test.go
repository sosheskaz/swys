package cert_test

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rootcmd "github.com/sosheskaz/swys/cmd"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

func TestExampleConnectChoosesServerName(t *testing.T) {
	t.Parallel()
	identity := testcmd.CreateNetworkIdentity(t, rootcmd.NewCommand)
	// The server presents the localhost identity only to clients that ask for it.
	endpoint := newVirtualHostTLSServer(t, &identity)

	output, _, err := executeRootStreams(t, "cert", "connect", endpoint, "--servername", "localhost", "--ca", identity.CACert, "-f", "json")
	require.NoError(t, err)
	assert.Equal(t, certificateFileDER(t, identity.ServerCert), connectLeafDER(t, output))
	verification := decodeConnectVerification(t, output)
	assert.True(t, verification.Verified, "the leaf is verified against --servername: %s", verification.Error)

	output, _, err = executeRootStreams(t, "cert", "connect", endpoint, "--ca", identity.CACert, "-f", "json")
	require.NoError(t, err)
	assert.NotEqual(t, certificateFileDER(t, identity.ServerCert), connectLeafDER(t, output), "an IP endpoint sends no SNI")
}

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

func TestExampleConnectOffersALPN(t *testing.T) {
	t.Parallel()
	identity := testcmd.CreateNetworkIdentity(t, rootcmd.NewCommand)
	// Like an ACME TLS-ALPN-01 responder, the server presents a challenge
	// certificate only to clients that offer acme-tls/1.
	endpoint, challenge := newACMEChallengeTLSServer(t, &identity)

	output, _, err := executeRootStreams(t, "cert", "connect", endpoint, "--alpn", "acme-tls/1", "-f", "json")
	require.NoError(t, err)
	assert.Equal(t, challenge, connectLeafDER(t, output))

	output, _, err = executeRootStreams(t, "cert", "connect", endpoint, "-f", "json")
	require.NoError(t, err)
	assert.Equal(t, certificateFileDER(t, identity.ServerCert), connectLeafDER(t, output))
}

func TestExampleConnectPresentsClientCertificate(t *testing.T) {
	t.Parallel()
	identity := testcmd.CreateNetworkIdentity(t, rootcmd.NewCommand)
	endpoint := newClientAuthTLSServer(t, &identity, tls.VersionTLS12)

	_, _, err := executeRootStreams(t, "cert", "connect", endpoint)
	require.ErrorContains(t, err, "handshake", "the TLS 1.2 server rejects a client without a certificate")

	output, _, err := executeRootStreams(t, "cert", "connect", endpoint,
		"--cert", identity.ClientCert, "--key", identity.ClientKey, "--ca", identity.CACert, "-f", "json")
	require.NoError(t, err)
	assert.Equal(t, certificateFileDER(t, identity.ServerCert), connectLeafDER(t, output))
	verification := decodeConnectVerification(t, output)
	assert.True(t, verification.Verified, "verification error: %s", verification.Error)
}

func TestExampleConnectResolvesEndpointAddress(t *testing.T) {
	t.Parallel()
	identity := testcmd.CreateNetworkIdentityFor(t, rootcmd.NewCommand, "service.test")
	_, port, err := net.SplitHostPort(newIdentityTLSServer(t, &identity))
	require.NoError(t, err)
	// service.test does not resolve; the override supplies its address while
	// SNI and verification keep the requested name.
	endpoint := net.JoinHostPort("service.test", port)

	output, _, err := executeRootStreams(t, "cert", "connect", endpoint, "--resolve", endpoint+":127.0.0.1", "--ca", identity.CACert, "-f", "json")
	require.NoError(t, err)
	assert.Equal(t, certificateFileDER(t, identity.ServerCert), connectLeafDER(t, output))
	verification := decodeConnectVerification(t, output)
	assert.True(t, verification.Verified, "verification error: %s", verification.Error)
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

func connectLeafDER(t *testing.T, output string) []byte {
	t.Helper()
	var report struct {
		Certificates []struct {
			PEM string `json:"pem"`
		} `json:"certificates"`
	}
	require.NoError(t, json.Unmarshal([]byte(output), &report))
	require.NotEmpty(t, report.Certificates)
	return singlePEMCertificate(t, report.Certificates[0].PEM)
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
