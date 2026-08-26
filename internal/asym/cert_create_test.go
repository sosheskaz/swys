package asym

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
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
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
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
			if cert.KeyUsage != wantUsage {
				t.Fatalf("key usage = %v, want %v", cert.KeyUsage, wantUsage)
			}
			if len(cert.ExtKeyUsage) != 2 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || cert.ExtKeyUsage[1] != x509.ExtKeyUsageClientAuth {
				t.Fatalf("extended key usage = %v", cert.ExtKeyUsage)
			}
			if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
				t.Fatalf("check self-signature: %v", err)
			}
			if cert.SignatureAlgorithm == x509.SHA1WithRSA || cert.SignatureAlgorithm == x509.DSAWithSHA1 || cert.SignatureAlgorithm == x509.ECDSAWithSHA1 {
				t.Fatalf("insecure signature algorithm = %s", cert.SignatureAlgorithm)
			}
			wantPublic, err := key.Public()
			if err != nil {
				t.Fatal(err)
			}
			wantDER, err := x509.MarshalPKIXPublicKey(wantPublic)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(cert.RawSubjectPublicKeyInfo, wantDER) {
				t.Fatal("certificate public key does not match subject key")
			}
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
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IsCA || !ca.BasicConstraintsValid || ca.MaxPathLen != 0 || !ca.MaxPathLenZero {
		t.Fatalf("CA constraints = IsCA:%t valid:%t pathlen:%d pathlen-zero:%t", ca.IsCA, ca.BasicConstraintsValid, ca.MaxPathLen, ca.MaxPathLenZero)
	}
	if ca.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Fatalf("CA key usage = %v", ca.KeyUsage)
	}

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
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(leafDER)
			if err != nil {
				t.Fatal(err)
			}
			if err := leaf.CheckSignatureFrom(ca); err != nil {
				t.Fatalf("check issuer signature: %v", err)
			}
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
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey := mustGenerateKey(t, KeyAlgorithmEd25519)
	options := CertificateOptions{
		Subject:      pkix.Name{CommonName: "leaf"},
		ValidFor:     30 * 24 * time.Hour,
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	nonCA := *ca
	nonCA.IsCA = false
	if _, err := createCertificateAt(&options, leafKey, &nonCA, caKey, now, rand.Reader); !errors.Is(err, ErrIssuerNotCA) {
		t.Fatalf("non-CA error = %v, want ErrIssuerNotCA", err)
	}

	badConstraints := *ca
	badConstraints.BasicConstraintsValid = false
	if _, err := createCertificateAt(&options, leafKey, &badConstraints, caKey, now, rand.Reader); !errors.Is(err, ErrIssuerNotCA) {
		t.Fatalf("invalid constraints error = %v, want ErrIssuerNotCA", err)
	}

	badUsage := *ca
	badUsage.KeyUsage = x509.KeyUsageDigitalSignature
	if _, err := createCertificateAt(&options, leafKey, &badUsage, caKey, now, rand.Reader); !errors.Is(err, ErrIssuerNotCA) {
		t.Fatalf("invalid key usage error = %v, want ErrIssuerNotCA", err)
	}

	expired := *ca
	expired.NotAfter = now.Add(-time.Second)
	if _, err := createCertificateAt(&options, leafKey, &expired, caKey, now, rand.Reader); !errors.Is(err, ErrIssuerValidity) {
		t.Fatalf("expired issuer error = %v, want ErrIssuerValidity", err)
	}

	notYetValid := *ca
	notYetValid.NotBefore = now.Add(time.Second)
	if _, err := createCertificateAt(&options, leafKey, &notYetValid, caKey, now, rand.Reader); !errors.Is(err, ErrIssuerValidity) {
		t.Fatalf("future issuer error = %v, want ErrIssuerValidity", err)
	}

	longOptions := options
	longOptions.ValidFor = 400 * 24 * time.Hour
	if _, err := createCertificateAt(&longOptions, leafKey, ca, caKey, now, rand.Reader); !errors.Is(err, ErrIssuerValidity) {
		t.Fatalf("outliving leaf error = %v, want ErrIssuerValidity", err)
	}

	wrongKey := mustGenerateKey(t, KeyAlgorithmEd25519)
	if _, err := createCertificateAt(&options, leafKey, ca, wrongKey, now, rand.Reader); !errors.Is(err, ErrIssuerKeyMismatch) {
		t.Fatalf("mismatch error = %v, want ErrIssuerKeyMismatch", err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	ca.NotBefore = now

	leafKey := mustGenerateKey(t, KeyAlgorithmEd25519)
	options := CertificateOptions{
		Subject:      pkix.Name{CommonName: "leaf"},
		ValidFor:     30 * 24 * time.Hour,
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := createCertificateAt(&options, leafKey, ca, caKey, now, rand.Reader)
	if err != nil {
		t.Fatalf("fresh issuer error = %v, want success", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "no-key-usage-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caSigner.Public(), caSigner)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	if ca.KeyUsage != 0 {
		t.Fatalf("CA KeyUsage = %v, want absent extension", ca.KeyUsage)
	}

	leafKey := mustGenerateKey(t, KeyAlgorithmEd25519)
	leafDER, err := createCertificateAt(&CertificateOptions{
		Subject:      pkix.Name{CommonName: "leaf"},
		ValidFor:     time.Hour,
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, leafKey, ca, caKey, now, rand.Reader)
	if err != nil {
		t.Fatalf("create leaf with absent issuer KeyUsage: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("verify leaf from absent-KeyUsage CA: %v", err)
	}
}

func TestCreateCertificateRequestCarriesSubjectAndSANs(t *testing.T) {
	t.Parallel()

	key := mustGenerateKey(t, KeyAlgorithmECDSAP384)
	der, err := CreateCertificateRequest(&CertificateRequestOptions{
		Subject:     pkix.Name{CommonName: "service.internal"},
		DNSNames:    []string{"service.internal"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.10")},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	request, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.CheckSignature(); err != nil {
		t.Fatalf("check CSR signature: %v", err)
	}
	if request.Subject.CommonName != "service.internal" || len(request.DNSNames) != 1 || request.DNSNames[0] != "service.internal" {
		t.Fatalf("CSR = subject:%q DNS:%v", request.Subject.CommonName, request.DNSNames)
	}
	if len(request.IPAddresses) != 1 || !request.IPAddresses[0].Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("CSR IP SANs = %v", request.IPAddresses)
	}
}

func TestCertificateCreationRequiresPrivateKeys(t *testing.T) {
	t.Parallel()

	private := mustGenerateKey(t, KeyAlgorithmEd25519)
	publicDER, err := private.Marshal(KeyFormatPKIXDER)
	if err != nil {
		t.Fatal(err)
	}
	public, err := ParseKey(publicDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := public.Signer(); !errors.Is(err, ErrPrivateKeyRequired) {
		t.Fatalf("Signer error = %v, want ErrPrivateKeyRequired", err)
	}
	if _, err := CreateCertificateRequest(&CertificateRequestOptions{
		Subject: pkix.Name{CommonName: "public-only"},
	}, public); !errors.Is(err, ErrPrivateKeyRequired) {
		t.Fatalf("CSR error = %v, want ErrPrivateKeyRequired", err)
	}
}

func mustGenerateKey(t *testing.T, algorithm KeyAlgorithm) *Key {
	t.Helper()
	material, err := GeneratePrivateKey(algorithm)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewKey(material)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
