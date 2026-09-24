package asym

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChainPEMFormatterSingle(t *testing.T) {
	t.Parallel()
	cert := generateTestCert(t)
	info := NewCertInfo(cert)

	formatter := &ChainPEMFormatter{}
	var buf bytes.Buffer
	err := formatter.Format(info, &buf)
	require.NoError(t, err)

	// Single cert should produce no output (no chain)
	assert.Empty(t, buf.Bytes())
}

func TestChainPEMFormatterMultiple(t *testing.T) {
	t.Parallel()
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t, func(c *x509.Certificate) {
		c.Subject.CommonName = "Intermediate CA"
	})
	cert3 := generateTestCert(t, func(c *x509.Certificate) {
		c.Subject.CommonName = "Root CA"
	})

	info1 := NewCertInfo(cert1)
	info2 := NewCertInfo(cert2)
	info3 := NewCertInfo(cert3)

	formatter := &ChainPEMFormatter{}
	var buf bytes.Buffer
	err := formatter.FormatMultiple([]*CertInfo{info1, info2, info3}, &buf)
	require.NoError(t, err)

	output := buf.String()

	// Should have 2 PEM blocks (excluding first/leaf cert)
	count := strings.Count(output, "-----BEGIN CERTIFICATE-----")
	assert.Equal(t, 2, count)

	// Verify we can parse them back
	var certs []*CertInfo
	remainder := []byte(output)
	for len(remainder) > 0 {
		block, rest := pem.Decode(remainder)
		if block == nil {
			break
		}
		info, err := NewCertInfoFromDER(block.Bytes)
		require.NoError(t, err)
		certs = append(certs, info)
		remainder = rest
	}

	assert.Len(t, certs, 2)
}

func TestPEMFormatterFullChainSingle(t *testing.T) {
	t.Parallel()
	cert := generateTestCert(t)
	info := NewCertInfo(cert)

	formatter := &PEMFormatter{FullChain: true}
	var buf bytes.Buffer
	err := formatter.Format(info, &buf)
	require.NoError(t, err)

	output := buf.String()

	// Should have 1 PEM block
	count := strings.Count(output, "-----BEGIN CERTIFICATE-----")
	assert.Equal(t, 1, count)
}

func TestPEMFormatterFullChainMultiple(t *testing.T) {
	t.Parallel()
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t, func(c *x509.Certificate) {
		c.Subject.CommonName = "Intermediate CA"
	})
	cert3 := generateTestCert(t, func(c *x509.Certificate) {
		c.Subject.CommonName = "Root CA"
	})

	info1 := NewCertInfo(cert1)
	info2 := NewCertInfo(cert2)
	info3 := NewCertInfo(cert3)

	formatter := &PEMFormatter{FullChain: true}
	var buf bytes.Buffer
	err := formatter.FormatMultiple([]*CertInfo{info1, info2, info3}, &buf)
	require.NoError(t, err)

	output := buf.String()

	// Should have 3 PEM blocks (all certs)
	count := strings.Count(output, "-----BEGIN CERTIFICATE-----")
	assert.Equal(t, 3, count)

	// Verify we can parse them back
	var certs []*CertInfo
	remainder := []byte(output)
	for len(remainder) > 0 {
		block, rest := pem.Decode(remainder)
		if block == nil {
			break
		}
		info, err := NewCertInfoFromDER(block.Bytes)
		require.NoError(t, err)
		certs = append(certs, info)
		remainder = rest
	}

	assert.Len(t, certs, 3)
}

func TestChainPEMFormatterEmptyChain(t *testing.T) {
	t.Parallel()
	cert := generateTestCert(t)
	info := NewCertInfo(cert)

	formatter := &ChainPEMFormatter{}
	var buf bytes.Buffer
	err := formatter.FormatMultiple([]*CertInfo{info}, &buf)
	require.NoError(t, err)

	// Single cert in array should still produce no output (no chain)
	assert.Empty(t, buf.Bytes())
}
