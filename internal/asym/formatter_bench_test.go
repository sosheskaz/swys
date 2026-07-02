package asym

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// benchCert is a pre-generated certificate for benchmarks.
var benchCert *x509.Certificate

func init() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1234567890),
		Subject: pkix.Name{
			CommonName:   "bench.example.com",
			Organization: []string{"Bench Org"},
			Country:      []string{"US"},
		},
		Issuer: pkix.Name{
			CommonName:   "Bench CA",
			Organization: []string{"Bench CA Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              []string{"bench.example.com", "www.bench.example.com", "api.bench.example.com"},
		IPAddresses:           []net.IP{net.ParseIP("192.168.1.1")},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}

	benchCert, err = x509.ParseCertificate(certDER)
	if err != nil {
		panic(err)
	}
}

func BenchmarkNewCertInfo(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		_, err := NewCertInfo(benchCert)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewCertInfoVerified(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		_, err := NewCertInfoVerified(benchCert)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewCertInfoVerifiedWarmed(b *testing.B) {
	// Warm up the cert pool cache
	_, _ = NewCertInfoVerified(benchCert)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, err := NewCertInfoVerified(benchCert)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTextFormatterCompact(b *testing.B) {
	info, _ := NewCertInfo(benchCert)
	formatter := &TextFormatter{Long: false}
	var buf bytes.Buffer

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		buf.Reset()
		_ = formatter.Format(info, &buf)
	}
}

func BenchmarkTextFormatterLong(b *testing.B) {
	info, _ := NewCertInfo(benchCert)
	info.Chains = [][]ChainCertInfo{
		{{Subject: "CN=test", Issuer: "CN=CA"}},
	}
	formatter := &TextFormatter{Long: true}
	var buf bytes.Buffer

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		buf.Reset()
		_ = formatter.Format(info, &buf)
	}
}

func BenchmarkJSONFormatter(b *testing.B) {
	info, _ := NewCertInfo(benchCert)
	formatter := &JSONFormatter{}
	var buf bytes.Buffer

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		buf.Reset()
		_ = formatter.Format(info, &buf)
	}
}

func BenchmarkPEMFormatter(b *testing.B) {
	info, _ := NewCertInfo(benchCert)
	formatter := &PEMFormatter{}
	var buf bytes.Buffer

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		buf.Reset()
		_ = formatter.Format(info, &buf)
	}
}

func BenchmarkFormatFingerprint(b *testing.B) {
	fp := make([]byte, 32) // SHA256 size
	rand.Read(fp)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = formatFingerprint(fp)
	}
}

func BenchmarkCommonName(b *testing.B) {
	info := &CertInfo{Subject: "CN=bench.example.com,O=Bench Org,C=US"}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = info.CommonName()
	}
}
