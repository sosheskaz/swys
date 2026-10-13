package cert_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
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

	rootcmd "github.com/sosheskaz/swys/cmd"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/commands/cert"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
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

func TestCertificateInspectRejectsHardLinkedOutput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	contents := []byte("preserve before parsing")
	inputPath := writeCertTestFile(t, dir, "input.pem", contents)
	outputPath := filepath.Join(dir, "output.pem")
	require.NoError(t, os.Link(inputPath, outputPath))
	root := newRootCmd()
	input := &certVerifyReadCounter{}
	root.SetIn(input)

	stdout, _, err := executeRootCommandStreams(t, root, "cert", "inspect", "--input", inputPath, "--output", outputPath)
	require.ErrorIs(t, err, errCertificatePathCollision)
	assert.Zero(t, input.count.Load())
	assert.Empty(t, stdout)
	preserved, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	assert.Equal(t, contents, preserved)
}

func TestCertificateInspectAcceptsDERAndPreservesFraming(t *testing.T) {
	t.Parallel()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{})
	for _, test := range []struct {
		wantErr error
		name    string
		data    []byte
		reject  bool
	}{
		{name: "single DER certificate", data: fixture.leafDER},
		{name: "DER trailing whitespace", data: append(bytes.Clone(fixture.leafDER), '\n'), reject: true},
		{
			name: "PEM trailing data", data: append(bytes.Clone(fixture.leafPEM), []byte("trailing data")...),
			reject: true, wantErr: errTrailingCertificateData,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			stdout, _, err := executeCertTestWithInput(t, test.data, "cert", "inspect", "-f", "pem")
			if test.reject {
				require.Error(t, err)
				if test.wantErr != nil {
					require.ErrorIs(t, err, test.wantErr)
				}
				assert.Empty(t, stdout)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, string(fixture.leafPEM), stdout)
		})
	}
}

func TestCertificateInspectDescribesUnverifiedCertificates(t *testing.T) {
	t.Parallel()
	first := newCertVerifyMatchFixture(t, certFixtureOptions{})
	second := newCertVerifyMatchFixture(t, certFixtureOptions{})
	expired := newCertVerifyMatchFixture(t, certFixtureOptions{
		leafNotBefore: time.Unix(0, 0), leafNotAfter: time.Unix(3600, 0),
	})
	restricted := newCertVerifyMatchFixture(t, certFixtureOptions{
		extKeyUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		leafNotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		leafNotAfter:  time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	for _, test := range []struct {
		name    string
		pems    [][]byte
		expired bool
	}{
		{name: "unrelated CAs", pems: [][]byte{first.rootPEM, second.rootPEM}},
		{name: "expired certificate", pems: [][]byte{expired.leafPEM}, expired: true},
		{name: "restricted purpose", pems: [][]byte{restricted.leafPEM}},
	} {
		for _, format := range []string{"text", "plain", "json", "pem"} {
			t.Run(test.name+"/"+format, func(t *testing.T) {
				t.Parallel()
				input := bytes.Join(test.pems, nil)
				stdout, stderr, err := executeCertTestWithInput(t, input, "cert", "inspect", "--format", format)
				require.NoError(t, err)
				assert.Empty(t, stderr)
				switch format {
				case "pem":
					assert.Equal(t, string(input), stdout)
				case "json":
					var report struct {
						Certificates []struct {
							PEM         string   `json:"pem"`
							ExtKeyUsage []string `json:"ext_key_usage"`
							IsExpired   bool     `json:"is_expired"`
						} `json:"certificates"`
						Verification json.RawMessage `json:"verification"`
					}
					require.NoError(t, json.Unmarshal([]byte(stdout), &report))
					assert.Nil(t, report.Verification)
					require.Len(t, report.Certificates, len(test.pems))
					for index, want := range test.pems {
						assert.Equal(t, string(want), report.Certificates[index].PEM)
						assert.Equal(t, test.expired, report.Certificates[index].IsExpired)
					}
					if test.name == "restricted purpose" {
						assert.Equal(t, []string{"Code Signing"}, report.Certificates[0].ExtKeyUsage)
					}
				default:
					assert.NotContains(t, stdout, "Verification")
					assert.NotContains(t, stdout, "not verified")
					for index := range test.pems {
						assert.Contains(t, stdout, fmt.Sprintf("Certificate %d", index+1))
					}
				}
			})
		}
	}
}

func TestCertificateSupportedFormatsDriveHelpErrorsAndCompletion(t *testing.T) {
	t.Parallel()
	wantFormats := []string{"json", "pem", "plain", "text"}
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
				"Subject    ", "Issuer     ", "Serial     ", "DNS Names  ", "IPs        ", "Not Before  ", "Not After   ",
				"Key                ", "SHA256             ", "Public Key SHA256  ",
			} {
				assert.Contains(t, output, field, "default format")
				assert.Contains(t, explicit, field, "explicit text format")
			}
			if command[1] == "connect" {
				assert.Contains(t, output, "Certificate Verification · original leaf")
				assert.Contains(t, explicit, "Certificate Verification · original leaf")
			} else {
				assert.NotContains(t, output, "Verification")
				assert.NotContains(t, explicit, "Verification")
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
