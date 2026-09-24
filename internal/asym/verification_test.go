package asym

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)
	require.Len(t, infos, 2)
	assert.True(t, infos[0].Verified, "leaf verification: %s", infos[0].VerifyError)
	assert.True(t, infos[1].Verified, "intermediate verification: %s", infos[1].VerifyError)
	var output bytes.Buffer
	require.NoError(t, (&TextFormatter{Long: true}).Format(infos[0], &output))
	assert.Contains(t, output.String(), "Test, Root", "chain output should preserve the comma in the common name")
	leafOnly, err := NewCertInfos([]*x509.Certificate{leaf, intermediate}, &x509.VerifyOptions{
		DNSName: "service.example.com",
		Roots:   roots,
	}, false)
	require.NoError(t, err)
	assert.Len(t, leafOnly, 1)

	wrongHost, err := NewCertInfos([]*x509.Certificate{leaf, intermediate}, &x509.VerifyOptions{
		DNSName: "other.example.com",
		Roots:   roots,
	}, true)
	require.NoError(t, err)
	require.NotEmpty(t, wrongHost)
	assert.False(t, wrongHost[0].Verified, "leaf unexpectedly verified for the wrong hostname")
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
	require.NoError(t, err)
	require.NotEmpty(t, infos)
	assert.Equal(t, "Service, Leaf", infos[0].CommonName())
	require.Len(t, infos[0].Chains, 1)
	require.Len(t, infos[0].Chains[0], 3)
	chain := infos[0].Chains[0]
	assert.Equal(t, "Service, Leaf", chain[0].CommonName)
	assert.Equal(t, "Test, Root", chain[2].CommonName)
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

	_, err := NewCertInfoVerified(leaf, options)
	require.NoError(t, err)
	assert.True(t, options.CurrentTime.IsZero(), "NewCertInfoVerified mutated the caller's CurrentTime")
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
	require.NoError(t, err)
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
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}
