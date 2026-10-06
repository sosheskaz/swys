package cert_test

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExampleConnectExportsRootAsBase64PEM(t *testing.T) {
	t.Parallel()
	server := newChainTLSServer(t)
	certificates := server.TLS.Certificates[0].Certificate
	output, diagnostics, err := executeRootStreams(t, "cert", "connect", server.Listener.Addr().String(), "--select", "0", "-f", "pem", "-e", "base64")
	require.NoError(t, err)
	decoded, err := base64.StdEncoding.DecodeString(output)
	require.NoError(t, err)
	block, rest := pem.Decode(decoded)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
	assert.Equal(t, certificates[len(certificates)-1], block.Bytes)
	assert.Empty(t, rest)
	assert.Contains(t, diagnostics, "not verified")

	inspected, _, err := executeCertTestWithInput(t, []byte(output), "cert", "inspect", "--input-encoding", "base64", "-f", "pem")
	require.NoError(t, err, "inspect the encoded certificate export")
	assert.Equal(t, string(decoded), inspected)
}

func TestExampleConnectExtractsPEMFromJSON(t *testing.T) {
	t.Parallel()
	server := newChainTLSServer(t)
	output, diagnostics, err := executeRootStreams(t, "cert", "connect", server.Listener.Addr().String(), "-f", "json")
	require.NoError(t, err)
	var report struct {
		Certificates []struct {
			PEM    string `json:"pem"`
			Source string `json:"source"`
		} `json:"certificates"`
		Selection    string `json:"selection"`
		Verification struct {
			Error    string `json:"error"`
			Verified bool   `json:"verified"`
		} `json:"verification"`
	}

	require.NoError(t, json.Unmarshal([]byte(output), &report))
	assert.Equal(t, "leaf", report.Selection)
	require.Len(t, report.Certificates, 1)
	block, rest := pem.Decode([]byte(report.Certificates[0].PEM))
	require.NotNil(t, block)
	assert.Equal(t, server.TLS.Certificates[0].Certificate[0], block.Bytes)
	assert.Empty(t, rest)
	assert.Equal(t, "peer", report.Certificates[0].Source)
	assert.False(t, report.Verification.Verified)
	assert.NotEmpty(t, report.Verification.Error)
	assert.Empty(t, diagnostics)
}
