package cert_test

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCertCreateFromCSRExample exercises the supported CLI flow: a caller
// supplies a signed request and CA material, then receives the issued leaf.
func TestCertCreateFromCSRExample(t *testing.T) {
	t.Parallel()
	fixture := newCSRIssueFixture(t)
	requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "service.example", Organization: []string{"npc example"}},
		DNSNames:    []string{"service.example"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.25")},
	})
	request := parseCSRIssueRequest(t, requestDER)
	requestPath := fixture.writeDER(t, "service.csr.b64", []byte(base64.StdEncoding.EncodeToString(requestDER)))
	requestBefore, err := os.ReadFile(requestPath)
	require.NoError(t, err)
	issuerPEM, err := os.ReadFile(fixture.caCertPath)
	require.NoError(t, err)
	issuerKeyPEM, err := os.ReadFile(fixture.caKeyPath)
	require.NoError(t, err)
	issuerPath := fixture.writeDER(t, "issuer.hex", []byte(hex.EncodeToString(issuerPEM)))
	issuerKeyPath := fixture.writeDER(t, "issuer-key.b32", []byte(base32.StdEncoding.EncodeToString(issuerKeyPEM)))
	certificatePath := filepath.Join(t.TempDir(), "service.pem")

	args := []string{
		"cert", "create", "--csr", requestPath, "--csr-encoding", "base64",
		"--issuer-cert", issuerPath, "--issuer-cert-encoding", "hex",
		"--issuer-key", issuerKeyPath, "--issuer-key-encoding", "base32", "--output", certificatePath,
	}
	if _, _, err := executeRootStreams(t, args...); err != nil {
		t.Fatal(err)
	}
	certificate := readSingleCertificate(t, certificatePath)
	if err := certificate.CheckSignatureFrom(fixture.ca); err != nil {
		t.Fatalf("check issuer signature: %v", err)
	}
	if !bytes.Equal(certificate.RawSubjectPublicKeyInfo, request.RawSubjectPublicKeyInfo) {
		t.Fatal("issued certificate does not contain the CSR public key")
	}
	identityChanged := !bytes.Equal(certificate.RawSubject, request.RawSubject) ||
		len(certificate.DNSNames) != 1 || certificate.DNSNames[0] != "service.example" ||
		len(certificate.IPAddresses) != 1 || !certificate.IPAddresses[0].Equal(net.ParseIP("192.0.2.25"))
	if identityChanged {
		t.Fatalf("issued identity = subject:%q DNS:%v IP:%v", certificate.Subject, certificate.DNSNames, certificate.IPAddresses)
	}
	unexpectedUsage := len(certificate.ExtKeyUsage) != 2 ||
		certificate.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth ||
		certificate.ExtKeyUsage[1] != x509.ExtKeyUsageClientAuth
	if unexpectedUsage {
		t.Fatalf("issued ExtKeyUsage = %v, want server and client authentication", certificate.ExtKeyUsage)
	}
	requestAfter, err := os.ReadFile(requestPath)
	require.NoError(t, err)
	if !bytes.Equal(requestAfter, requestBefore) {
		t.Fatal("CSR source changed during issuance")
	}
}

func TestExampleCertCreateAndCSRFromEncodedKey(t *testing.T) {
	t.Parallel()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{})
	keyPath := writeCertTestFile(t, t.TempDir(), "service-key.b64url", []byte(base64.RawURLEncoding.EncodeToString(fixture.leafKeyPKCS8PEM)))

	for _, operation := range []string{"create", "csr"} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			stdout, stderr, err := executeRootStreams(t, "cert", operation,
				"--key", keyPath, "--key-encoding", "base64url", "--dns", "service.example",
			)
			require.NoError(t, err, "stderr %q", stderr)
			if operation == "create" {
				certificate := parseCSRIssueCertificatePEM(t, []byte(stdout))
				require.Equal(t, fixture.leaf.RawSubjectPublicKeyInfo, certificate.RawSubjectPublicKeyInfo)
				require.Equal(t, []string{"service.example"}, certificate.DNSNames)
				return
			}
			block, rest := pem.Decode([]byte(stdout))
			require.NotNil(t, block)
			require.Empty(t, rest)
			request := parseCSRIssueRequest(t, block.Bytes)
			require.NoError(t, request.CheckSignature())
			require.Equal(t, fixture.leaf.RawSubjectPublicKeyInfo, request.RawSubjectPublicKeyInfo)
			require.Equal(t, []string{"service.example"}, request.DNSNames)
		})
	}
}
