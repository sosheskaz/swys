package asym

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// generateTestCert creates a self-signed test certificate.
func generateTestCert(t *testing.T, opts ...func(*x509.Certificate)) *x509.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1234567890),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              []string{"test.example.com", "www.test.example.com"},
		IPAddresses:           []net.IP{net.ParseIP("192.168.1.1")},
		BasicConstraintsValid: true,
	}

	// Apply options
	for _, opt := range opts {
		opt(template)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func TestNewCertInfo(t *testing.T) {
	cert := generateTestCert(t)
	info, err := NewCertInfo(cert)
	if err != nil {
		t.Fatalf("NewCertInfo failed: %v", err)
	}

	// Check subject
	if !strings.Contains(info.Subject, "test.example.com") {
		t.Errorf("expected subject to contain 'test.example.com', got %s", info.Subject)
	}

	// Check DNS names
	if len(info.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names, got %d", len(info.DNSNames))
	}

	// Check IP addresses
	if len(info.IPAddresses) != 1 {
		t.Errorf("expected 1 IP address, got %d", len(info.IPAddresses))
	}
	if info.IPAddresses[0] != "192.168.1.1" {
		t.Errorf("expected IP 192.168.1.1, got %s", info.IPAddresses[0])
	}

	// Check key usage
	if len(info.KeyUsage) == 0 {
		t.Error("expected key usage to be set")
	}

	// Check ext key usage
	if len(info.ExtKeyUsage) != 2 {
		t.Errorf("expected 2 ext key usages, got %d", len(info.ExtKeyUsage))
	}

	// Check fingerprint is set
	if info.SHA256Fingerprint == "" {
		t.Error("expected SHA256 fingerprint to be set")
	}

	// Check RawDER is set
	if len(info.RawDER) == 0 {
		t.Error("expected RawDER to be set")
	}
}

func TestCertInfoCommonName(t *testing.T) {
	cert := generateTestCert(t)
	info, _ := NewCertInfo(cert)

	cn := info.CommonName()
	if cn != "test.example.com" {
		t.Errorf("expected CommonName 'test.example.com', got '%s'", cn)
	}
}

func TestTextFormatterCompact(t *testing.T) {
	cert := generateTestCert(t)
	info, _ := NewCertInfo(cert)
	info.Verified = true

	formatter := &TextFormatter{Long: false}
	var buf bytes.Buffer
	err := formatter.Format(info, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := buf.String()

	// Check status indicator
	if !strings.Contains(output, "+ test.example.com") {
		t.Errorf("expected verified indicator '+', got:\n%s", output)
	}

	// Check DNS names line (2 DNS names should not be truncated)
	if !strings.Contains(output, "DNS: test.example.com, www.test.example.com") {
		t.Errorf("expected DNS names in output, got:\n%s", output)
	}
}

func TestTextFormatterCompactManyDNS(t *testing.T) {
	cert := generateTestCert(t, func(c *x509.Certificate) {
		c.DNSNames = []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"}
	})
	info, _ := NewCertInfo(cert)
	info.Verified = true

	formatter := &TextFormatter{Long: false}
	var buf bytes.Buffer
	err := formatter.Format(info, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := buf.String()

	// Check that DNS names are truncated with "and X more"
	if !strings.Contains(output, "and 2 more") {
		t.Errorf("expected truncated DNS names with 'and 2 more', got:\n%s", output)
	}
	// Should show first 3
	if !strings.Contains(output, "a.example.com, b.example.com, c.example.com") {
		t.Errorf("expected first 3 DNS names, got:\n%s", output)
	}
	// Should not show the 4th one in full
	if strings.Contains(output, "d.example.com, e.example.com") {
		t.Errorf("should not show all DNS names, got:\n%s", output)
	}
}

func TestTextFormatterCompactUnverified(t *testing.T) {
	cert := generateTestCert(t)
	info, _ := NewCertInfo(cert)
	info.Verified = false
	info.VerifyError = "certificate signed by unknown authority"

	formatter := &TextFormatter{Long: false}
	var buf bytes.Buffer
	err := formatter.Format(info, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := buf.String()

	// Check status indicator
	if !strings.Contains(output, "x test.example.com") {
		t.Errorf("expected unverified indicator 'x', got:\n%s", output)
	}

	// Check error message
	if !strings.Contains(output, "Error: certificate signed by unknown authority") {
		t.Errorf("expected error message in output, got:\n%s", output)
	}
}

func TestTextFormatterLong(t *testing.T) {
	cert := generateTestCert(t)
	info, _ := NewCertInfo(cert)
	info.Verified = true
	info.Chains = [][]ChainCertInfo{
		{
			{Subject: "CN=test.example.com", Issuer: "CN=Test CA"},
			{Subject: "CN=Test CA", Issuer: "CN=Root CA"},
		},
	}

	formatter := &TextFormatter{Long: true}
	var buf bytes.Buffer
	err := formatter.Format(info, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := buf.String()

	// Check that it includes detailed fields
	if !strings.Contains(output, "Subject:") {
		t.Errorf("expected Subject in long output, got:\n%s", output)
	}
	if !strings.Contains(output, "Serial:") {
		t.Errorf("expected Serial in long output, got:\n%s", output)
	}
	if !strings.Contains(output, "SHA256:") {
		t.Errorf("expected SHA256 fingerprint in long output, got:\n%s", output)
	}
	if !strings.Contains(output, "Chains:") {
		t.Errorf("expected Chains in long output, got:\n%s", output)
	}
}

func TestTextFormatterMultiple(t *testing.T) {
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t, func(c *x509.Certificate) {
		c.Subject.CommonName = "other.example.com"
		c.DNSNames = []string{"other.example.com"}
	})

	info1, _ := NewCertInfo(cert1)
	info2, _ := NewCertInfo(cert2)

	formatter := &TextFormatter{Long: false}
	var buf bytes.Buffer
	err := formatter.FormatMultiple([]*CertInfo{info1, info2}, &buf)
	if err != nil {
		t.Fatalf("FormatMultiple failed: %v", err)
	}

	output := buf.String()

	// Check both certs are present
	if !strings.Contains(output, "test.example.com") {
		t.Errorf("expected first cert in output, got:\n%s", output)
	}
	if !strings.Contains(output, "other.example.com") {
		t.Errorf("expected second cert in output, got:\n%s", output)
	}
}

func TestJSONFormatter(t *testing.T) {
	cert := generateTestCert(t)
	info, _ := NewCertInfo(cert)
	info.Verified = true

	formatter := &JSONFormatter{}
	var buf bytes.Buffer
	err := formatter.Format(info, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Verify it's valid JSON
	var parsed CertInfo
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput:\n%s", err, buf.String())
	}

	// Check fields
	if parsed.Subject == "" {
		t.Error("expected subject in JSON output")
	}
	if len(parsed.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names in JSON, got %d", len(parsed.DNSNames))
	}
}

func TestJSONFormatterMultiple(t *testing.T) {
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t, func(c *x509.Certificate) {
		c.Subject.CommonName = "other.example.com"
	})

	info1, _ := NewCertInfo(cert1)
	info2, _ := NewCertInfo(cert2)

	formatter := &JSONFormatter{}
	var buf bytes.Buffer
	err := formatter.FormatMultiple([]*CertInfo{info1, info2}, &buf)
	if err != nil {
		t.Fatalf("FormatMultiple failed: %v", err)
	}

	// Verify it's valid JSON array
	var parsed []*CertInfo
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON array: %v\nOutput:\n%s", err, buf.String())
	}

	if len(parsed) != 2 {
		t.Errorf("expected 2 certs in JSON array, got %d", len(parsed))
	}
}

func TestPEMFormatter(t *testing.T) {
	cert := generateTestCert(t)
	info, _ := NewCertInfo(cert)

	formatter := &PEMFormatter{}
	var buf bytes.Buffer
	err := formatter.Format(info, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := buf.String()

	// Check PEM format
	if !strings.Contains(output, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("expected PEM header, got:\n%s", output)
	}
	if !strings.Contains(output, "-----END CERTIFICATE-----") {
		t.Errorf("expected PEM footer, got:\n%s", output)
	}

	// Verify it can be decoded
	block, _ := pem.Decode(buf.Bytes())
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("expected CERTIFICATE type, got %s", block.Type)
	}

	// Verify DER can be parsed back
	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse DER from PEM: %v", err)
	}
}

func TestPEMFormatterMultiple(t *testing.T) {
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t)

	info1, _ := NewCertInfo(cert1)
	info2, _ := NewCertInfo(cert2)

	formatter := &PEMFormatter{}
	var buf bytes.Buffer
	err := formatter.FormatMultiple([]*CertInfo{info1, info2}, &buf)
	if err != nil {
		t.Fatalf("FormatMultiple failed: %v", err)
	}

	output := buf.String()

	// Count PEM blocks
	count := strings.Count(output, "-----BEGIN CERTIFICATE-----")
	if count != 2 {
		t.Errorf("expected 2 PEM blocks, got %d", count)
	}
}

func TestExtractCN(t *testing.T) {
	tests := []struct {
		name string
		dn   string
		want string
	}{
		{"cn only", "CN=example.com", "example.com"},
		{"cn first with trailing attrs", "CN=example.com,O=Acme,C=US", "example.com"},
		{"cn not first", "O=Acme,CN=example.com", "example.com"},
		{"cn last of several", "OU=IT,O=Acme Corp,C=US,CN=example.com", "example.com"},
		{"escaped comma before cn", `O=Acme\, Inc.,CN=example.com`, "example.com"},
		{"escaped comma inside cn value", `CN=foo\, bar,O=Acme`, `foo\, bar`},
		{"no cn present", "O=Acme,C=US", "O=Acme,C=US"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractCN(tt.dn); got != tt.want {
				t.Errorf("extractCN(%q) = %q, want %q", tt.dn, got, tt.want)
			}
		})
	}
}

// TestTextFormatterLongChainCN_HandlesEscapedComma exercises format_text.go's
// own chain-CN rendering (a second, separately-maintained CN parser) to prove
// it shares the escaping bug, not just formatter.go's extractCN.
func TestTextFormatterLongChainCN_HandlesEscapedComma(t *testing.T) {
	cert := generateTestCert(t)
	info, _ := NewCertInfo(cert)
	info.Verified = true
	info.Chains = [][]ChainCertInfo{
		{
			{Subject: `CN=foo\, bar,O=Acme`, Issuer: "CN=Test CA"},
		},
	}

	formatter := &TextFormatter{Long: true}
	var buf bytes.Buffer
	if err := formatter.Format(info, &buf); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `foo\, bar`) {
		t.Errorf("expected chain entry to show CN %q, got:\n%s", `foo\, bar`, output)
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		expected string
		duration time.Duration
	}{
		{duration: 30 * 24 * time.Hour, expected: "30d"},
		{duration: 365 * 24 * time.Hour, expected: "365d"},
		{duration: 400 * 24 * time.Hour, expected: "1y35d"},
		{duration: 5 * time.Hour, expected: "5h"},
		{duration: 45 * time.Minute, expected: "45m"},
	}

	for _, tt := range tests {
		result := formatDuration(tt.duration)
		if result != tt.expected {
			t.Errorf("formatDuration(%v) = %s, want %s", tt.duration, result, tt.expected)
		}
	}
}

func TestFormatFingerprint(t *testing.T) {
	fp := []byte{0xAB, 0xCD, 0xEF, 0x12}
	result := formatFingerprint(fp)
	expected := "AB:CD:EF:12"
	if result != expected {
		t.Errorf("formatFingerprint = %s, want %s", result, expected)
	}
}

func TestExpiredCertificate(t *testing.T) {
	cert := generateTestCert(t, func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(-24 * time.Hour) // Expired yesterday
	})

	info, _ := NewCertInfo(cert)

	if !info.IsExpired {
		t.Error("expected IsExpired to be true")
	}
	if info.RemainingTime != "expired" {
		t.Errorf("expected RemainingTime 'expired', got '%s'", info.RemainingTime)
	}
}

func TestCACertificate(t *testing.T) {
	cert := generateTestCert(t, func(c *x509.Certificate) {
		c.IsCA = true
		c.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	})

	info, _ := NewCertInfo(cert)

	if !info.IsCA {
		t.Error("expected IsCA to be true")
	}

	// Check key usage includes cert sign
	found := false
	for _, usage := range info.KeyUsage {
		if usage == "Certificate Sign" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'Certificate Sign' in KeyUsage, got %v", info.KeyUsage)
	}
}
