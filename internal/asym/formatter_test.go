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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCert creates a self-signed test certificate.
func generateTestCert(t *testing.T, opts ...func(*x509.Certificate)) *x509.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "failed to generate key")

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
	require.NoError(t, err, "failed to create certificate")

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err, "failed to parse certificate")

	return cert
}

func TestNewCertInfo(t *testing.T) {
	t.Parallel()
	cert := generateTestCert(t)
	info := NewCertInfo(cert)

	// Check subject
	assert.Contains(t, info.Subject, "test.example.com")

	// Check DNS names
	assert.Len(t, info.DNSNames, 2)

	// Check IP addresses
	require.Len(t, info.IPAddresses, 1)
	assert.Equal(t, "192.168.1.1", info.IPAddresses[0])

	// Check key usage
	assert.NotEmpty(t, info.KeyUsage)

	// Check ext key usage
	assert.Len(t, info.ExtKeyUsage, 2)

	// Check fingerprint is set
	assert.NotEmpty(t, info.SHA256Fingerprint)
	publicKeyFingerprint, err := info.PublicKeySHA256Fingerprint()
	require.NoError(t, err)
	key, err := NewKey(cert.PublicKey)
	require.NoError(t, err)
	keyInfo, err := key.Info()
	require.NoError(t, err)
	require.Equal(t, keyInfo.PublicKeySHA256Fingerprint, publicKeyFingerprint, "certificate public-key fingerprint")

	// Check RawDER is set
	assert.NotEmpty(t, info.RawDER)
}

func TestCertInfoCommonName(t *testing.T) {
	t.Parallel()
	cert := generateTestCert(t)
	info := NewCertInfo(cert)

	cn := info.CommonName()
	assert.Equal(t, "test.example.com", cn)
}

func TestTextFormatterCompact(t *testing.T) {
	t.Parallel()
	cert := generateTestCert(t)
	info := NewCertInfo(cert)
	info.Verified = true

	formatter := &TextFormatter{Long: false}
	var buf bytes.Buffer
	err := formatter.Format(info, &buf)
	require.NoError(t, err, "Format")

	output := buf.String()

	// Check status indicator
	assert.Contains(t, output, "+ test.example.com")

	// Check DNS names line (2 DNS names should not be truncated)
	assert.Contains(t, output, "DNS: test.example.com, www.test.example.com")
}

func TestTextFormatterCompactManyDNS(t *testing.T) {
	t.Parallel()
	cert := generateTestCert(t, func(c *x509.Certificate) {
		c.DNSNames = []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"}
	})
	info := NewCertInfo(cert)
	info.Verified = true

	formatter := &TextFormatter{Long: false}
	var buf bytes.Buffer
	err := formatter.Format(info, &buf)
	require.NoError(t, err, "Format")

	output := buf.String()

	// Check that DNS names are truncated with "and X more"
	assert.Contains(t, output, "and 2 more")
	// Should show first 3
	assert.Contains(t, output, "a.example.com, b.example.com, c.example.com")
	// Should not show the 4th one in full
	assert.NotContains(t, output, "d.example.com, e.example.com")
}

func TestTextFormatterCompactUnverified(t *testing.T) {
	t.Parallel()
	cert := generateTestCert(t)
	info := NewCertInfo(cert)
	info.Verified = false
	info.VerifyError = "certificate signed by unknown authority"

	formatter := &TextFormatter{Long: false}
	var buf bytes.Buffer
	err := formatter.Format(info, &buf)
	require.NoError(t, err, "Format")

	output := buf.String()

	// Check status indicator
	assert.Contains(t, output, "x test.example.com")

	// Check error message
	assert.Contains(t, output, "Error: certificate signed by unknown authority")
}

func TestTextFormatterLong(t *testing.T) {
	t.Parallel()
	cert := generateTestCert(t)
	info := NewCertInfo(cert)
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
	require.NoError(t, err, "Format")

	output := buf.String()

	// Check that it includes detailed fields
	assert.Contains(t, output, "Subject:")
	assert.Contains(t, output, "Serial:")
	assert.Contains(t, output, "SHA256:")
	assert.Contains(t, output, "Public Key SHA256:")
	assert.Contains(t, output, "Chains:")
}

func TestTextFormatterLongHandlesUnknownPublicKeyAlgorithm(t *testing.T) {
	t.Parallel()
	cert := generateTestCert(t)
	cert.PublicKeyAlgorithm = x509.UnknownPublicKeyAlgorithm
	cert.PublicKey = nil
	info := NewCertInfo(cert)

	var buf bytes.Buffer
	require.NoError(t, (&TextFormatter{Long: true}).Format(info, &buf), "Format")
	require.Contains(t, buf.String(), "Public Key SHA256: (unavailable)")
}

func TestTextFormatterMultiple(t *testing.T) {
	t.Parallel()
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t, func(c *x509.Certificate) {
		c.Subject.CommonName = "other.example.com"
		c.DNSNames = []string{"other.example.com"}
	})

	info1 := NewCertInfo(cert1)
	info2 := NewCertInfo(cert2)

	formatter := &TextFormatter{Long: false}
	var buf bytes.Buffer
	err := formatter.FormatMultiple([]*CertInfo{info1, info2}, &buf)
	require.NoError(t, err, "FormatMultiple")

	output := buf.String()

	// Check both certs are present
	assert.Contains(t, output, "test.example.com")
	assert.Contains(t, output, "other.example.com")
}

func TestJSONFormatter(t *testing.T) {
	t.Parallel()
	cert := generateTestCert(t)
	info := NewCertInfo(cert)
	info.Verified = true

	formatter := &JSONFormatter{}
	var buf bytes.Buffer
	err := formatter.Format(info, &buf)
	require.NoError(t, err, "Format")

	// Verify it's valid JSON
	var parsed CertInfo
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput:\n%s", err, buf.String())
	}

	// Check fields
	assert.NotEmpty(t, parsed.Subject)
	assert.Len(t, parsed.DNSNames, 2)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &fields))
	wantFingerprint, err := info.PublicKeySHA256Fingerprint()
	require.NoError(t, err)
	require.Equal(t, wantFingerprint, fields["public_key_sha256_fingerprint"], "public_key_sha256_fingerprint")
}

func TestJSONFormatterMultiple(t *testing.T) {
	t.Parallel()
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t, func(c *x509.Certificate) {
		c.Subject.CommonName = "other.example.com"
	})

	info1 := NewCertInfo(cert1)
	info2 := NewCertInfo(cert2)

	formatter := &JSONFormatter{}
	var buf bytes.Buffer
	err := formatter.FormatMultiple([]*CertInfo{info1, info2}, &buf)
	require.NoError(t, err, "FormatMultiple")

	// Verify it's valid JSON array
	var parsed []*CertInfo
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON array: %v\nOutput:\n%s", err, buf.String())
	}

	assert.Len(t, parsed, 2)
}

func TestPEMFormatter(t *testing.T) {
	t.Parallel()
	cert := generateTestCert(t)
	info := NewCertInfo(cert)

	formatter := &PEMFormatter{}
	var buf bytes.Buffer
	err := formatter.Format(info, &buf)
	require.NoError(t, err, "Format")

	output := buf.String()

	// Check PEM format
	assert.Contains(t, output, "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, output, "-----END CERTIFICATE-----")

	// Verify it can be decoded
	block, _ := pem.Decode(buf.Bytes())
	require.NotNil(t, block, "failed to decode PEM block")
	assert.Equal(t, "CERTIFICATE", block.Type)

	// Verify DER can be parsed back
	_, err = x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "failed to parse DER from PEM")
}

func TestPEMFormatterMultiple(t *testing.T) {
	t.Parallel()
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t)

	info1 := NewCertInfo(cert1)
	info2 := NewCertInfo(cert2)

	formatter := &PEMFormatter{}
	var buf bytes.Buffer
	err := formatter.FormatMultiple([]*CertInfo{info1, info2}, &buf)
	require.NoError(t, err, "FormatMultiple")

	output := buf.String()

	// Count PEM blocks
	count := strings.Count(output, "-----BEGIN CERTIFICATE-----")
	assert.Equal(t, 2, count)
}

func TestTextFormatterLongChainCNHandlesComma(t *testing.T) {
	t.Parallel()
	cert := generateTestCert(t)
	info := NewCertInfo(cert)
	info.Verified = true
	info.Chains = [][]ChainCertInfo{
		{
			{Subject: `CN=foo\, bar,O=Acme`, Issuer: "CN=Test CA", CommonName: "foo, bar"},
		},
	}

	formatter := &TextFormatter{Long: true}
	var buf bytes.Buffer
	require.NoError(t, formatter.Format(info, &buf), "Format")

	output := buf.String()
	assert.Contains(t, output, "foo, bar")
}

func TestFormatDuration(t *testing.T) {
	t.Parallel()
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
		assert.Equal(t, tt.expected, result, "formatDuration(%v)", tt.duration)
	}
}

func TestFormatFingerprint(t *testing.T) {
	t.Parallel()
	fp := []byte{0xAB, 0xCD, 0xEF, 0x12}
	result := formatFingerprint(fp)
	expected := "AB:CD:EF:12"
	assert.Equal(t, expected, result)
}

func TestExpiredCertificate(t *testing.T) {
	t.Parallel()
	cert := generateTestCert(t, func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(-24 * time.Hour) // Expired yesterday
	})

	info := NewCertInfo(cert)

	assert.True(t, info.IsExpired)
	assert.Equal(t, "expired", info.RemainingTime)
}

func TestCACertificate(t *testing.T) {
	t.Parallel()
	cert := generateTestCert(t, func(c *x509.Certificate) {
		c.IsCA = true
		c.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	})

	info := NewCertInfo(cert)

	assert.True(t, info.IsCA)

	// Check key usage includes cert sign
	assert.Contains(t, info.KeyUsage, "Certificate Sign")
}
