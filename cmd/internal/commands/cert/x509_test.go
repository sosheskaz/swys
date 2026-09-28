package cert_test

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rootcmd "github.com/sosheskaz-systems/npc/cmd"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/commands/cert"
	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
)

func TestX509CommandRejectsPrivateKeyPEM(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "key.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")})
	require.NoError(t, os.WriteFile(path, data, 0o600))

	output, err := executeRoot(t, "cert", "inspect", "--input", path)
	require.ErrorIs(t, err, errUnexpectedPEMType, "error = %v, want errUnexpectedPEMType", err)
	require.ErrorContains(t, err, "PRIVATE KEY", "want the offending block type reported")
	assert.Empty(t, output, "output = %q, want no output for invalid input", output)
}

func TestCertificateSupportedFormatsDriveHelpErrorsAndCompletion(t *testing.T) {
	t.Parallel()
	wantFormats := []string{"chain", "fullchain", "json", "long", "pem", "text"}
	root := rootcmd.NewCommand()
	command, _, err := root.Find([]string{"cert", "inspect"})
	require.NoError(t, err)
	flag := command.Flags().Lookup(commandio.FormatFlagName)
	require.NotNil(t, flag, "format flag not registered")
	assert.Contains(t, flag.Usage, strings.Join(wantFormats, ", "), "format usage")
	completion, ok := command.GetFlagCompletionFunc(commandio.FormatFlagName)
	require.True(t, ok, "format has no completion function")
	values, _ := completion(command, nil, "")
	for i, value := range values {
		values[i], _, _ = strings.Cut(value, "\t")
	}
	assert.Equal(t, wantFormats, values, "format completions")

	_, err = executeRoot(t, "cert", "inspect", "--format", "missing")
	assert.ErrorContains(t, err, "(valid: "+strings.Join(wantFormats, ", ")+")", "format error should list the supported values")
}

func TestCertificateFormatRejectsLegacyEncodingWithMigrationHint(t *testing.T) {
	t.Parallel()
	_, err := executeRoot(t, "cert", "inspect", "--format", "hex")
	require.ErrorIs(t, err, cert.ErrFormatSelectsStructuredOutput)
}

func TestConnectCommandFormatsCertificateChain(t *testing.T) {
	t.Parallel()
	server := newChainTLSServer(t)
	certificates := server.TLS.Certificates[0].Certificate
	tests := []struct {
		format string
		want   [][]byte
	}{
		{format: "pem", want: certificates[:1]},
		{format: "chain", want: certificates[1:]},
		{format: "fullchain", want: certificates},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			t.Parallel()
			output, _, err := executeRootStreams(t, "cert", "connect", server.Listener.Addr().String(), "--format", tt.format)
			require.NoError(t, err)
			var got [][]byte
			for remaining := []byte(output); len(bytes.TrimSpace(remaining)) > 0; {
				block, rest := pem.Decode(remaining)
				require.NotNil(t, block, "invalid certificate PEM")
				assert.Equal(t, "CERTIFICATE", block.Type)
				got = append(got, block.Bytes)
				remaining = rest
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConnectCommandPreservesEndpointSNI(t *testing.T) {
	t.Parallel()
	serverName := make(chan string, 1)
	server := newChainTLSServerWithClientHello(t, func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		serverName <- hello.ServerName
		return nil, nil //nolint:nilnil // nil directs TLS to continue with the existing configuration
	})
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	require.NoError(t, err)

	if _, err := executeRoot(t, "cert", "connect", net.JoinHostPort("localhost", port)); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-serverName:
		if got != "localhost" {
			t.Fatalf("SNI = %q, want localhost", got)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive ClientHello")
	}
}

func newChainTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	return newChainTLSServerWithClientHello(t, nil)
}

func newChainTLSServerWithClientHello(
	t *testing.T,
	getConfigForClient func(*tls.ClientHelloInfo) (*tls.Config, error),
) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates:       []tls.Certificate{testcmd.NewTLSCertificateChain(t)},
		GetConfigForClient: getConfigForClient,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}
