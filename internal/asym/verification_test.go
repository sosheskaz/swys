package asym

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestNewCertInfosVerifiesHostnameAndPeerIntermediates(t *testing.T) {
	t.Parallel()
	leaf, intermediate, root := generateCertificateChain(t)
	roots := x509.NewCertPool()
	roots.AddCert(root)

	infos, err := NewCertInfos([]*x509.Certificate{leaf, intermediate}, &x509.VerifyOptions{
		DNSName: "service.example.com",
		Roots:   roots,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !infos[0].Verified {
		t.Fatalf("leaf was not verified: %s", infos[0].VerifyError)
	}
	if !infos[1].Verified {
		t.Fatalf("intermediate was not verified: %s", infos[1].VerifyError)
	}
	var output bytes.Buffer
	if err := (&TextFormatter{Long: true}).Format(infos[0], &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Test, Root") {
		t.Fatalf("chain output did not preserve comma in common name:\n%s", output.String())
	}
	leafOnly, err := NewCertInfos([]*x509.Certificate{leaf, intermediate}, &x509.VerifyOptions{
		DNSName: "service.example.com",
		Roots:   roots,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(leafOnly) != 1 {
		t.Fatalf("leaf-only info count = %d, want 1", len(leafOnly))
	}

	wrongHost, err := NewCertInfos([]*x509.Certificate{leaf, intermediate}, &x509.VerifyOptions{
		DNSName: "other.example.com",
		Roots:   roots,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if wrongHost[0].Verified {
		t.Fatal("leaf unexpectedly verified for the wrong hostname")
	}
}

func TestNewCertInfosPreservesCommonNamesContainingCommas(t *testing.T) {
	t.Parallel()
	leaf, intermediate, root := generateCertificateChain(t)
	roots := x509.NewCertPool()
	roots.AddCert(root)

	infos, err := NewCertInfos([]*x509.Certificate{leaf, intermediate}, &x509.VerifyOptions{
		DNSName: "service.example.com",
		Roots:   roots,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := infos[0].CommonName(); got != "Service, Leaf" {
		t.Fatalf("leaf common name = %q, want %q", got, "Service, Leaf")
	}
	if len(infos[0].Chains) != 1 || len(infos[0].Chains[0]) != 3 {
		t.Fatalf("verified chains = %#v, want one three-certificate chain", infos[0].Chains)
	}
	chain := infos[0].Chains[0]
	if got := chain[0].CommonName; got != "Service, Leaf" {
		t.Fatalf("chain leaf common name = %q, want %q", got, "Service, Leaf")
	}
	if got := chain[2].CommonName; got != "Test, Root" {
		t.Fatalf("chain root common name = %q, want %q", got, "Test, Root")
	}
}

func TestNewCertInfoVerifiedDoesNotMutateOptions(t *testing.T) {
	t.Parallel()
	leaf, intermediate, root := generateCertificateChain(t)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	options := &x509.VerifyOptions{
		DNSName:       "service.example.com",
		Roots:         roots,
		Intermediates: intermediates,
	}

	if _, err := NewCertInfoVerified(leaf, options); err != nil {
		t.Fatal(err)
	}
	if !options.CurrentTime.IsZero() {
		t.Fatal("NewCertInfoVerified mutated the caller's CurrentTime")
	}
}

func generateCertificateChain(t *testing.T) (*x509.Certificate, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	now := time.Now()
	rootKey := generateECDSAKey(t)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test, Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	root := createCertificate(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)

	intermediateKey := generateECDSAKey(t)
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(12 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intermediate := createCertificate(t, intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)

	leafKey := generateECDSAKey(t)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Service, Leaf"},
		DNSNames:     []string{"service.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(6 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leaf := createCertificate(t, leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)
	return leaf, intermediate, root
}

func generateECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func createCertificate(
	t *testing.T,
	template *x509.Certificate,
	parent *x509.Certificate,
	publicKey *ecdsa.PublicKey,
	signer *ecdsa.PrivateKey,
) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
