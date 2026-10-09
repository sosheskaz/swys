package asym

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/internal/textdisplay"
)

func TestCertificateVerificationReportAlignsAvailableFields(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		want         string
		verification CertificateVerification
	}{
		{
			verification: CertificateVerification{Error: "unknown authority"},
			want:         "\n  Certificate Verification · original leaf\n    Status  not verified\n    Error   unknown authority\n",
		},
		{
			verification: CertificateVerification{Verified: true, chainNames: [][]ChainCertInfo{{{CommonName: "leaf"}, {CommonName: "root"}}}},
			want:         "\n  Certificate Verification · original leaf\n    Status   verified\n    Chain 1  leaf -> root\n",
		},
	} {
		var output bytes.Buffer
		require.NoError(t, test.verification.WriteReport(&output, textdisplay.Options{}))
		assert.Equal(t, test.want, output.String())
	}
}

func TestCertificateReportPreservesNamesAndLeafVerification(t *testing.T) {
	t.Parallel()
	leaf, intermediate, root := generateCertificateChain(t)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	report, err := InspectCertificates([]*x509.Certificate{leaf, intermediate, root}, &x509.VerifyOptions{
		DNSName: "service.example.com", Roots: roots,
	}, SelectLeaf, "peer")
	require.NoError(t, err)
	require.Len(t, report.Certificates, 1)
	assert.True(t, report.Verification.Verified)
	require.Len(t, report.Verification.Chains, 1)
	assert.Equal(t, []string{
		NewCertInfo(leaf).SHA256Fingerprint, NewCertInfo(intermediate).SHA256Fingerprint, NewCertInfo(root).SHA256Fingerprint,
	}, report.Verification.Chains[0])
	var output bytes.Buffer
	require.NoError(t, (&TextFormatter{}).FormatReport(report, &output))
	assert.Contains(t, output.String(), "Service, Leaf")
	assert.Contains(t, output.String(), "Service, Leaf -> Test Intermediate -> Test, Root")
	assert.Contains(t, output.String(), "certificate verification: verified")
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

func TestCertificateRootSelectionKeepsTrustSeparate(t *testing.T) {
	t.Parallel()
	leaf, intermediate, root := generateCertificateChain(t)
	_, _, unrelated := generateCertificateChain(t)
	trusted := x509.NewCertPool()
	trusted.AddCert(root)
	for _, test := range []struct {
		roots        *x509.CertPool
		name         string
		hostname     string
		wantSource   string
		certs        []*x509.Certificate
		wantVerified bool
		wantError    bool
	}{
		{
			name: "omitted trusted root", certs: []*x509.Certificate{leaf, intermediate},
			roots: trusted, hostname: "service.example.com", wantSource: "verified_chain", wantVerified: true,
		},
		{
			name: "supplied trusted root", certs: []*x509.Certificate{leaf, intermediate, root},
			roots: trusted, hostname: "service.example.com", wantSource: "peer", wantVerified: true,
		},
		{name: "private root", certs: []*x509.Certificate{leaf, intermediate, root}, roots: x509.NewCertPool(), wantSource: "peer"},
		{name: "wrong hostname", certs: []*x509.Certificate{leaf, intermediate, root}, roots: trusted, hostname: "other.example.com", wantSource: "peer"},
		{name: "missing root", certs: []*x509.Certificate{leaf, intermediate}, roots: x509.NewCertPool(), wantError: true},
		{name: "unrelated root", certs: []*x509.Certificate{leaf, intermediate, unrelated}, roots: x509.NewCertPool(), wantError: true},
		{name: "chain gap", certs: []*x509.Certificate{leaf, root}, roots: x509.NewCertPool(), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			report, err := InspectCertificates(test.certs, &x509.VerifyOptions{Roots: test.roots, DNSName: test.hostname}, SelectRoot, "peer")
			if test.wantError {
				require.ErrorIs(t, err, ErrCertificateSelection)
				return
			}
			require.NoError(t, err)
			require.Len(t, report.Certificates, 1)
			assert.Equal(t, root.Raw, report.Certificates[0].RawDER)
			assert.Equal(t, test.wantSource, report.Certificates[0].Source)
			assert.Equal(t, test.wantVerified, report.Verification.Verified)
			if !test.wantVerified {
				assert.NotEmpty(t, report.Verification.Error)
			}
		})
	}
}

func TestCertificateSelectionEmptyChainFails(t *testing.T) {
	t.Parallel()
	leaf, _, _ := generateCertificateChain(t)
	_, err := InspectCertificates([]*x509.Certificate{leaf}, &x509.VerifyOptions{Roots: x509.NewCertPool()}, SelectChain, "input")
	require.ErrorIs(t, err, ErrCertificateSelection)
}

func TestCertificateRootSelectionDeduplicatesCrossSignedPaths(t *testing.T) {
	t.Parallel()
	now := time.Now()
	roots := x509.NewCertPool()
	var supplied []*x509.Certificate
	var expected []string
	intermediateKey := generateECDSAKey(t)
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "Cross-signed intermediate"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
	}
	for i := range 2 {
		key := generateECDSAKey(t)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: fmt.Sprintf("Root %d", i)},
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		}
		root := createCertificate(t, template, template, &key.PublicKey, key)
		roots.AddCert(root)
		expected = append(expected, NewCertInfo(root).SHA256Fingerprint)
		// Two distinct issuers can lead to the same root; export that root only once.
		for j := range i + 1 {
			intermediateTemplate.SerialNumber = big.NewInt(int64(10 + i*2 + j))
			supplied = append(supplied, createCertificate(t, intermediateTemplate, root, &intermediateKey.PublicKey, key))
		}
	}
	leafKey := generateECDSAKey(t)
	leaf := createCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(20), Subject: pkix.Name{CommonName: "Leaf"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
	}, supplied[0], &leafKey.PublicKey, intermediateKey)
	supplied = append([]*x509.Certificate{leaf}, supplied...)
	report, err := InspectCertificates(supplied, &x509.VerifyOptions{Roots: roots}, SelectRoot, "peer")
	require.NoError(t, err)
	assert.True(t, report.Verification.Verified)
	require.Len(t, report.Verification.Chains, 3)
	require.Len(t, report.Certificates, 2)
	slices.Sort(expected)
	for i, cert := range report.Certificates {
		assert.Equal(t, expected[i], cert.SHA256Fingerprint)
		assert.Equal(t, "verified_chain", cert.Source)
	}
	_, err = InspectCertificates(supplied, &x509.VerifyOptions{Roots: roots}, "0", "peer")
	require.ErrorIs(t, err, ErrCertificateSelection)
	assert.ErrorContains(t, err, "ambiguous")
}

func TestCertificateIndexRunsFromRootToLeaf(t *testing.T) {
	t.Parallel()
	leaf, intermediate, root := generateCertificateChain(t)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	for index, want := range []*x509.Certificate{root, intermediate, leaf} {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			t.Parallel()
			report, err := InspectCertificates([]*x509.Certificate{leaf, intermediate}, &x509.VerifyOptions{Roots: roots}, strconv.Itoa(index), "peer")
			require.NoError(t, err)
			require.Len(t, report.Certificates, 1)
			assert.Equal(t, want.Raw, report.Certificates[0].RawDER)
			assert.True(t, report.Verification.Verified)
		})
	}
	report, err := InspectCertificates([]*x509.Certificate{leaf, intermediate, root}, &x509.VerifyOptions{Roots: x509.NewCertPool()}, "1", "input")
	require.NoError(t, err)
	require.Len(t, report.Certificates, 1)
	assert.Equal(t, intermediate.Raw, report.Certificates[0].RawDER)
	assert.False(t, report.Verification.Verified)
}
