package cert_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
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
	wantFormats := []string{"json", "pem", "text"}
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
		selection string
		want      [][]byte
	}{
		{selection: "leaf", want: certificates[:1]},
		{selection: "chain", want: certificates[1:]},
		{selection: "fullchain", want: certificates},
	}
	for _, tt := range tests {
		t.Run(tt.selection, func(t *testing.T) {
			t.Parallel()
			output, _, err := executeRootStreams(t, "cert", "connect", server.Listener.Addr().String(), "--format", "pem", "--select", tt.selection)
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

func TestCertificateTextIncludesDetails(t *testing.T) {
	t.Parallel()
	server := newChainTLSServer(t)
	input := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.TLS.Certificates[0].Certificate[0]})
	for _, command := range [][]string{{"cert", "inspect"}, {"cert", "connect", server.Listener.Addr().String()}} {
		t.Run(command[1], func(t *testing.T) {
			t.Parallel()
			output, stderr, err := executeCertTestWithInput(t, input, command...)
			require.NoError(t, err)
			assert.Empty(t, stderr)
			explicit, explicitStderr, err := executeCertTestWithInput(t, input, append(slices.Clone(command), "--format", "text")...)
			require.NoError(t, err)
			assert.Empty(t, explicitStderr)
			for _, field := range []string{
				"Subject:", "Issuer:", "Serial:", "DNS Names:", "IPs:", "Not Before:", "Not After:",
				"Key:", "SHA256:", "Public Key SHA256:", "certificate verification:",
			} {
				assert.Contains(t, output, field, "default format")
				assert.Contains(t, explicit, field, "explicit text format")
			}
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

func TestCertificateValidationFailurePreservesOutput(t *testing.T) {
	t.Parallel()
	server := newChainTLSServer(t)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.TLS.Certificates[0].Certificate[0]})
	for _, test := range []struct {
		name       string
		diagnostic string
		args       []string
	}{
		{name: "removed inspect format", args: []string{"cert", "inspect", "--format", "long"}, diagnostic: "unknown output format"},
		{name: "removed connect format", args: []string{"cert", "connect", server.Listener.Addr().String(), "--format", "long"}, diagnostic: "unknown output format"},
		{name: "missing root", args: []string{"cert", "inspect", "--select", "root"}, diagnostic: "root unavailable"},
		{name: "numeric missing root", args: []string{"cert", "inspect", "--select", "0"}, diagnostic: "root unavailable"},
		{name: "negative index", args: []string{"cert", "inspect", "--select", "-1"}, diagnostic: "non-negative decimal index"},
		{name: "overflow index", args: []string{"cert", "inspect", "--select", "999999999999999999999999999999999"}, diagnostic: "non-negative decimal index"},
		{
			name: "out of range index", args: []string{"cert", "connect", server.Listener.Addr().String(), "--select", "2"},
			diagnostic: "index 2 out of range (valid: 0..1",
		},
		{name: "empty chain", args: []string{"cert", "inspect", "--select", "chain"}, diagnostic: "no issuer certificates"},
		{name: "invalid selection", args: []string{"cert", "inspect", "--select", "missing"}, diagnostic: "unknown selection"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "existing.pem")
			require.NoError(t, os.WriteFile(path, []byte("preserve me"), 0o600))
			args := append(slices.Clone(test.args), "--output", path)
			_, _, err := executeCertTestWithInput(t, certificate, args...)
			require.ErrorContains(t, err, test.diagnostic)
			after, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, "preserve me", string(after))
		})
	}
}

func TestCertificateInspectSelectionIsIndependentOfFormat(t *testing.T) {
	t.Parallel()
	server := newChainTLSServer(t)
	certificates := server.TLS.Certificates[0].Certificate
	var input []byte
	for _, der := range certificates {
		input = append(input, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	for _, selection := range []string{"leaf", "chain", "fullchain", "root", "0", "1"} {
		t.Run(selection, func(t *testing.T) {
			t.Parallel()
			pemOutput, _, err := executeCertTestWithInput(t, input, "cert", "inspect", "-s", selection, "-f", "pem")
			require.NoError(t, err)
			jsonOutput, stderr, err := executeCertTestWithInput(t, input, "cert", "inspect", "--select", selection, "-f", "json")
			require.NoError(t, err)
			var report struct {
				Selection    string `json:"selection"`
				Certificates []struct {
					PEM    string `json:"pem"`
					Source string `json:"source"`
				} `json:"certificates"`
			}
			require.NoError(t, json.Unmarshal([]byte(jsonOutput), &report))
			assert.Equal(t, selection, report.Selection)
			var joined strings.Builder
			for _, cert := range report.Certificates {
				joined.WriteString(cert.PEM)
				assert.Equal(t, "input", cert.Source)
			}
			assert.Equal(t, pemOutput, joined.String())
			assert.Empty(t, stderr)
		})
	}
}
