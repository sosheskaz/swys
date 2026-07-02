package asym

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestChainPEMFormatterSingle(t *testing.T) {
	cert := generateTestCert(t)
	info, _ := NewCertInfo(cert)

	formatter := &ChainPEMFormatter{}
	var buf bytes.Buffer
	err := formatter.Format(info, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Single cert should produce no output (no chain)
	if buf.Len() != 0 {
		t.Errorf("expected no output for single cert, got %d bytes", buf.Len())
	}
}

func TestChainPEMFormatterMultiple(t *testing.T) {
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t, func(c *x509.Certificate) {
		c.Subject.CommonName = "Intermediate CA"
	})
	cert3 := generateTestCert(t, func(c *x509.Certificate) {
		c.Subject.CommonName = "Root CA"
	})

	info1, _ := NewCertInfo(cert1)
	info2, _ := NewCertInfo(cert2)
	info3, _ := NewCertInfo(cert3)

	formatter := &ChainPEMFormatter{}
	var buf bytes.Buffer
	err := formatter.FormatMultiple([]*CertInfo{info1, info2, info3}, &buf)
	if err != nil {
		t.Fatalf("FormatMultiple failed: %v", err)
	}

	output := buf.String()

	// Should have 2 PEM blocks (excluding first/leaf cert)
	count := strings.Count(output, "-----BEGIN CERTIFICATE-----")
	if count != 2 {
		t.Errorf("expected 2 PEM blocks, got %d", count)
	}

	// Verify we can parse them back
	var certs []*CertInfo
	remainder := []byte(output)
	for len(remainder) > 0 {
		block, rest := pem.Decode(remainder)
		if block == nil {
			break
		}
		info, err := NewCertInfoFromDER(block.Bytes)
		if err != nil {
			t.Fatalf("failed to parse cert: %v", err)
		}
		certs = append(certs, info)
		remainder = rest
	}

	if len(certs) != 2 {
		t.Errorf("expected 2 parsed certs, got %d", len(certs))
	}
}

func TestFullChainPEMFormatterSingle(t *testing.T) {
	cert := generateTestCert(t)
	info, _ := NewCertInfo(cert)

	formatter := &FullChainPEMFormatter{}
	var buf bytes.Buffer
	err := formatter.Format(info, &buf)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := buf.String()

	// Should have 1 PEM block
	count := strings.Count(output, "-----BEGIN CERTIFICATE-----")
	if count != 1 {
		t.Errorf("expected 1 PEM block, got %d", count)
	}
}

func TestFullChainPEMFormatterMultiple(t *testing.T) {
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t, func(c *x509.Certificate) {
		c.Subject.CommonName = "Intermediate CA"
	})
	cert3 := generateTestCert(t, func(c *x509.Certificate) {
		c.Subject.CommonName = "Root CA"
	})

	info1, _ := NewCertInfo(cert1)
	info2, _ := NewCertInfo(cert2)
	info3, _ := NewCertInfo(cert3)

	formatter := &FullChainPEMFormatter{}
	var buf bytes.Buffer
	err := formatter.FormatMultiple([]*CertInfo{info1, info2, info3}, &buf)
	if err != nil {
		t.Fatalf("FormatMultiple failed: %v", err)
	}

	output := buf.String()

	// Should have 3 PEM blocks (all certs)
	count := strings.Count(output, "-----BEGIN CERTIFICATE-----")
	if count != 3 {
		t.Errorf("expected 3 PEM blocks, got %d", count)
	}

	// Verify we can parse them back
	var certs []*CertInfo
	remainder := []byte(output)
	for len(remainder) > 0 {
		block, rest := pem.Decode(remainder)
		if block == nil {
			break
		}
		info, err := NewCertInfoFromDER(block.Bytes)
		if err != nil {
			t.Fatalf("failed to parse cert: %v", err)
		}
		certs = append(certs, info)
		remainder = rest
	}

	if len(certs) != 3 {
		t.Errorf("expected 3 parsed certs, got %d", len(certs))
	}
}

func TestChainPEMFormatterEmptyChain(t *testing.T) {
	cert := generateTestCert(t)
	info, _ := NewCertInfo(cert)

	formatter := &ChainPEMFormatter{}
	var buf bytes.Buffer
	err := formatter.FormatMultiple([]*CertInfo{info}, &buf)
	if err != nil {
		t.Fatalf("FormatMultiple failed: %v", err)
	}

	// Single cert in array should still produce no output (no chain)
	if buf.Len() != 0 {
		t.Errorf("expected no output for single cert in array, got %d bytes", buf.Len())
	}
}
