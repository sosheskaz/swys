package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParsePEMCertificates(t *testing.T) {
	t.Parallel()
	chain := newTLSCertificateChain(t).Certificate
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: chain[0]})
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: chain[1]})
	wrongType := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")})
	malformedDER := pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: []byte("not a certificate")})

	tests := []struct {
		wantErr   error
		name      string
		input     []byte
		wantCount int
	}{
		{name: "empty", wantErr: errNoPEMCertificates},
		{name: "whitespace", input: []byte(" \n\t"), wantErr: errNoPEMCertificates},
		{name: "one certificate", input: leafPEM, wantCount: 1},
		{name: "certificate chain", input: append(bytes.Clone(leafPEM), rootPEM...), wantCount: 2},
		{name: "surrounding whitespace", input: append(append([]byte(" \n"), leafPEM...), []byte("\t \n")...), wantCount: 1},
		{name: "malformed DER", input: malformedDER},
		{name: "wrong block type", input: wrongType, wantErr: errUnexpectedPEMType},
		{name: "garbage before", input: append([]byte("garbage\n"), leafPEM...), wantErr: errTrailingCertificateData},
		{name: "garbage between", input: append(append(bytes.Clone(leafPEM), []byte("garbage\n")...), rootPEM...), wantErr: errTrailingCertificateData},
		{name: "garbage after", input: append(bytes.Clone(leafPEM), []byte("garbage\n")...), wantErr: errTrailingCertificateData},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			certificates, err := parsePEMCertificates(test.input)
			if test.name == "malformed DER" {
				if err == nil || !strings.Contains(err.Error(), "parse PEM certificate") {
					t.Fatalf("error = %v, want malformed certificate error", err)
				}
				return
			}
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if len(certificates) != test.wantCount {
				t.Fatalf("certificate count = %d, want %d", len(certificates), test.wantCount)
			}
		})
	}
}

func TestX509CommandRejectsPrivateKeyPEM(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "key.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	output, err := executeRoot(t, "cert", "inspect", "--input", path)
	if !errors.Is(err, errUnexpectedPEMType) {
		t.Fatalf("error = %v, want errUnexpectedPEMType", err)
	}
	if !strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatalf("error = %v, want the offending block type reported", err)
	}
	if output != "" {
		t.Fatalf("output = %q, want no output for invalid input", output)
	}
}

func TestCertificateFormattersDeclareChainRequirements(t *testing.T) {
	t.Parallel()
	tests := []struct {
		format        string
		requiresChain bool
	}{
		{format: "text", requiresChain: false},
		{format: "pem", requiresChain: false},
		{format: "chain", requiresChain: true},
		{format: "fullchain", requiresChain: true},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			t.Parallel()
			formatter, err := getCertFormatter(tt.format)
			if err != nil {
				t.Fatal(err)
			}
			if got := formatter.RequiresChain(); got != tt.requiresChain {
				t.Fatalf("RequiresChain() = %t, want %t", got, tt.requiresChain)
			}
		})
	}
}

func TestConnectCommandUsesFormatterChainRequirement(t *testing.T) { //nolint:paralleltest // mutates a package-level formatter or encoding registry
	server := newChainTLSServer(t)
	// certFormatters is package-global; do not make this test parallel.
	tests := []struct {
		name         string
		formatter    string
		wantPEMCount int
	}{
		{name: "requires chain", formatter: "fullchain", wantPEMCount: 2},
		{name: "does not require chain", formatter: "pem", wantPEMCount: 1},
	}
	for _, tt := range tests { //nolint:paralleltest // subtests mutate the shared formatter registry
		t.Run(tt.name, func(t *testing.T) {
			formatName := "test-" + strings.ReplaceAll(tt.name, " ", "-")
			certFormatters[formatName] = certFormatters[tt.formatter]
			t.Cleanup(func() { delete(certFormatters, formatName) })

			output, err := executeRoot(
				t,
				"cert", "connect", server.Listener.Addr().String(), "--format", formatName,
			)
			if err != nil {
				t.Fatal(err)
			}
			if count := strings.Count(output, "-----BEGIN CERTIFICATE-----"); count != tt.wantPEMCount {
				t.Fatalf("formatter emitted %d certificates, want %d", count, tt.wantPEMCount)
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
	if err != nil {
		t.Fatal(err)
	}

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
		Certificates:       []tls.Certificate{newTLSCertificateChain(t)},
		GetConfigForClient: getConfigForClient,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func newTLSCertificateChain(t *testing.T) tls.Certificate {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}
}
