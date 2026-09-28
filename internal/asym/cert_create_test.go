package asym

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateCertificateSupportsValidatedSigningKeys(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		algorithm KeyAlgorithm
	}{
		{name: "ed25519", algorithm: KeyAlgorithmEd25519},
		{name: "p256", algorithm: KeyAlgorithmECDSAP256},
		{name: "p384", algorithm: KeyAlgorithmECDSAP384},
		{name: "rsa2048", algorithm: KeyAlgorithmRSA2048},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			key := mustGenerateKey(t, test.algorithm)
			der, err := createCertificateAt(&CertificateOptions{
				Subject:      pkix.Name{CommonName: "localhost"},
				DNSNames:     []string{"localhost"},
				IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
				ValidFor:     30 * 24 * time.Hour,
				ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			}, key, nil, nil, now, rand.Reader)
			require.NoError(t, err)
			cert, err := x509.ParseCertificate(der)
			require.NoError(t, err)
			if cert.SerialNumber.Sign() <= 0 || cert.SerialNumber.BitLen() > 128 {
				t.Fatalf("serial = %v, want positive value of at most 128 bits", cert.SerialNumber)
			}
			if !cert.NotBefore.Equal(now.Add(-5*time.Minute)) || !cert.NotAfter.Equal(now.Add(30*24*time.Hour)) {
				t.Fatalf("validity = %s..%s, want %s..%s", cert.NotBefore, cert.NotAfter, now.Add(-5*time.Minute), now.Add(30*24*time.Hour))
			}
			if cert.IsCA || !cert.BasicConstraintsValid {
				t.Fatalf("leaf constraints = IsCA:%t valid:%t", cert.IsCA, cert.BasicConstraintsValid)
			}
			wantUsage := x509.KeyUsageDigitalSignature
			if _, ok := cert.PublicKey.(*rsa.PublicKey); ok {
				wantUsage |= x509.KeyUsageKeyEncipherment
			}
			require.Equal(t, wantUsage, cert.KeyUsage, "key usage")
			require.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, cert.ExtKeyUsage)
			require.NoError(t, cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature), "check self-signature")
			if cert.SignatureAlgorithm == x509.SHA1WithRSA || cert.SignatureAlgorithm == x509.DSAWithSHA1 || cert.SignatureAlgorithm == x509.ECDSAWithSHA1 {
				t.Fatalf("insecure signature algorithm = %s", cert.SignatureAlgorithm)
			}
			wantPublic, err := key.Public()
			require.NoError(t, err)
			wantDER, err := x509.MarshalPKIXPublicKey(wantPublic)
			require.NoError(t, err)
			require.Equal(t, wantDER, cert.RawSubjectPublicKeyInfo, "certificate public key does not match subject key")
		})
	}
}

func TestCreateCertificateBuildsVerifiableMiniCAChain(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
	caKey := mustGenerateKey(t, KeyAlgorithmEd25519)
	caDER, err := createCertificateAt(&CertificateOptions{
		Subject:  pkix.Name{CommonName: "test-ca"},
		ValidFor: 365 * 24 * time.Hour,
		IsCA:     true,
	}, caKey, nil, nil, now, rand.Reader)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	if !ca.IsCA || !ca.BasicConstraintsValid || ca.MaxPathLen != 0 || !ca.MaxPathLenZero {
		t.Fatalf("CA constraints = IsCA:%t valid:%t pathlen:%d pathlen-zero:%t", ca.IsCA, ca.BasicConstraintsValid, ca.MaxPathLen, ca.MaxPathLenZero)
	}
	require.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, ca.KeyUsage, "CA key usage")

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, algorithm := range []KeyAlgorithm{
		KeyAlgorithmEd25519,
		KeyAlgorithmECDSAP256,
		KeyAlgorithmRSA2048,
	} {
		t.Run(string(algorithm), func(t *testing.T) {
			t.Parallel()

			leafKey := mustGenerateKey(t, algorithm)
			leafDER, err := createCertificateAt(&CertificateOptions{
				Subject:      pkix.Name{CommonName: "localhost"},
				DNSNames:     []string{"localhost"},
				ValidFor:     30 * 24 * time.Hour,
				ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}, leafKey, ca, caKey, now.Add(time.Minute), rand.Reader)
			require.NoError(t, err)
			leaf, err := x509.ParseCertificate(leafDER)
			require.NoError(t, err)
			require.NoError(t, leaf.CheckSignatureFrom(ca), "check issuer signature")
			if _, err := leaf.Verify(x509.VerifyOptions{
				Roots:       roots,
				DNSName:     "localhost",
				KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				CurrentTime: now.Add(time.Hour),
			}); err != nil {
				t.Fatalf("verify leaf: %v", err)
			}
		})
	}
}

func TestCreateCertificateRejectsInvalidIssuer(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
	caKey := mustGenerateKey(t, KeyAlgorithmEd25519)
	caDER, err := createCertificateAt(&CertificateOptions{
		Subject:  pkix.Name{CommonName: "test-ca"},
		ValidFor: 365 * 24 * time.Hour,
		IsCA:     true,
	}, caKey, nil, nil, now, rand.Reader)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	leafKey := mustGenerateKey(t, KeyAlgorithmEd25519)
	options := CertificateOptions{
		Subject:      pkix.Name{CommonName: "leaf"},
		ValidFor:     30 * 24 * time.Hour,
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	nonCA := *ca
	nonCA.IsCA = false
	_, err = createCertificateAt(&options, leafKey, &nonCA, caKey, now, rand.Reader)
	require.ErrorIs(t, err, ErrIssuerNotCA, "non-CA issuer")

	badConstraints := *ca
	badConstraints.BasicConstraintsValid = false
	_, err = createCertificateAt(&options, leafKey, &badConstraints, caKey, now, rand.Reader)
	require.ErrorIs(t, err, ErrIssuerNotCA, "invalid issuer constraints")

	badUsage := *ca
	badUsage.KeyUsage = x509.KeyUsageDigitalSignature
	_, err = createCertificateAt(&options, leafKey, &badUsage, caKey, now, rand.Reader)
	require.ErrorIs(t, err, ErrIssuerNotCA, "invalid issuer key usage")

	expired := *ca
	expired.NotAfter = now.Add(-time.Second)
	_, err = createCertificateAt(&options, leafKey, &expired, caKey, now, rand.Reader)
	require.ErrorIs(t, err, ErrIssuerValidity, "expired issuer")

	notYetValid := *ca
	notYetValid.NotBefore = now.Add(time.Second)
	_, err = createCertificateAt(&options, leafKey, &notYetValid, caKey, now, rand.Reader)
	require.ErrorIs(t, err, ErrIssuerValidity, "future issuer")

	longOptions := options
	longOptions.ValidFor = 400 * 24 * time.Hour
	_, err = createCertificateAt(&longOptions, leafKey, ca, caKey, now, rand.Reader)
	require.ErrorIs(t, err, ErrIssuerValidity, "leaf outlives issuer")

	wrongKey := mustGenerateKey(t, KeyAlgorithmEd25519)
	_, err = createCertificateAt(&options, leafKey, ca, wrongKey, now, rand.Reader)
	assert.ErrorIs(t, err, ErrIssuerKeyMismatch, "issuer key mismatch")
}

func TestCreateCertificateEnforcesIssuerValidityBounds(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
	caKey := mustGenerateKey(t, KeyAlgorithmEd25519)
	caDER, err := createCertificateAt(&CertificateOptions{
		Subject:  pkix.Name{CommonName: "test-ca"},
		ValidFor: 365 * 24 * time.Hour,
		IsCA:     true,
	}, caKey, nil, nil, now, rand.Reader)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	ca.NotBefore = now

	leafKey := mustGenerateKey(t, KeyAlgorithmEd25519)
	options := CertificateOptions{
		Subject:      pkix.Name{CommonName: "leaf"},
		ValidFor:     30 * 24 * time.Hour,
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := createCertificateAt(&options, leafKey, ca, caKey, now, rand.Reader)
	require.NoError(t, err, "fresh issuer")
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	if !leaf.NotBefore.Equal(ca.NotBefore) {
		t.Fatalf("leaf NotBefore = %s, want issuer NotBefore %s", leaf.NotBefore, ca.NotBefore)
	}

	options.ValidFor = 365 * 24 * time.Hour
	if _, err := createCertificateAt(&options, leafKey, ca, caKey, now.Add(time.Second), rand.Reader); !errors.Is(err, ErrIssuerValidity) {
		t.Fatalf("equal-duration leaf error = %v, want ErrIssuerValidity", err)
	}
	options.ValidFor = 364 * 24 * time.Hour
	if _, err := createCertificateAt(&options, leafKey, ca, caKey, now.Add(time.Second), rand.Reader); err != nil {
		t.Fatalf("shorter leaf error = %v, want success", err)
	}
}

func TestCreateCertificateAcceptsCAWithoutKeyUsageExtension(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
	caKey := mustGenerateKey(t, KeyAlgorithmEd25519)
	caSigner, err := caKey.Signer()
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "no-key-usage-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caSigner.Public(), caSigner)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	require.Zero(t, ca.KeyUsage, "absent CA KeyUsage extension")

	leafKey := mustGenerateKey(t, KeyAlgorithmEd25519)
	leafDER, err := createCertificateAt(&CertificateOptions{
		Subject:      pkix.Name{CommonName: "leaf"},
		ValidFor:     time.Hour,
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, leafKey, ca, caKey, now, rand.Reader)
	require.NoError(t, err, "create leaf with absent issuer KeyUsage")
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	require.NoError(t, leaf.CheckSignatureFrom(ca), "verify leaf from absent-KeyUsage CA")
}

func TestCreateCertificateRequestCarriesSubjectAndSANs(t *testing.T) {
	t.Parallel()

	key := mustGenerateKey(t, KeyAlgorithmECDSAP384)
	der, err := CreateCertificateRequest(&CertificateRequestOptions{
		Subject:     pkix.Name{CommonName: "service.internal"},
		DNSNames:    []string{"service.internal"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.10")},
	}, key)
	require.NoError(t, err)
	request, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	require.NoError(t, request.CheckSignature(), "check CSR signature")
	require.Equal(t, "service.internal", request.Subject.CommonName)
	require.Equal(t, []string{"service.internal"}, request.DNSNames)
	if len(request.IPAddresses) != 1 || !request.IPAddresses[0].Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("CSR IP SANs = %v", request.IPAddresses)
	}
}

func TestCertificateCreationRequiresPrivateKeys(t *testing.T) {
	t.Parallel()

	private := mustGenerateKey(t, KeyAlgorithmEd25519)
	publicDER, err := private.Marshal(KeyFormatPKIXDER)
	require.NoError(t, err)
	public, err := ParseKey(publicDER)
	require.NoError(t, err)
	_, err = public.Signer()
	require.ErrorIs(t, err, ErrPrivateKeyRequired)
	if _, err := CreateCertificateRequest(&CertificateRequestOptions{
		Subject: pkix.Name{CommonName: "public-only"},
	}, public); !errors.Is(err, ErrPrivateKeyRequired) {
		t.Fatalf("CSR error = %v, want ErrPrivateKeyRequired", err)
	}
}

func mustGenerateKey(t *testing.T, algorithm KeyAlgorithm) *Key {
	t.Helper()
	material, err := GeneratePrivateKey(algorithm)
	require.NoError(t, err)
	key, err := NewKey(material)
	require.NoError(t, err)
	return key
}
