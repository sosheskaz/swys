package cmd

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"os"
	"path/filepath"
	"testing"
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
	requestPath := fixture.writeRequest(t, "service.csr", requestDER, "CERTIFICATE REQUEST")
	requestBefore, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(t.TempDir(), "service.pem")

	args := append(fixture.issueArgs(requestPath), "--output", certificatePath)
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
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(requestAfter, requestBefore) {
		t.Fatal("CSR source changed during issuance")
	}
}
