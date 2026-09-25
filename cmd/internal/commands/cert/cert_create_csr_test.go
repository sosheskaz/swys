package cert_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/artifact"
	"github.com/sosheskaz-systems/npc/internal/asym"
)

var (
	csrIssueOIDSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	csrIssueOIDKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	csrIssueOIDExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	csrIssueOIDUnsupported      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}
)

func TestCertCreateCSRPreservesRawIdentityWithoutDefaults(t *testing.T) {
	t.Parallel()
	fixture := newCSRIssueFixture(t)
	rawSubject := marshalCSRIssueRDNSequence(t, pkix.RDNSequence{
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "npc"}, {Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "testing"}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"}},
	})
	requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{
		RawSubject:  rawSubject,
		DNSNames:    []string{"one.example", "two.example"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")},
	})
	requestPath := fixture.writeRequest(t, "identity.csr", requestDER, "CERTIFICATE REQUEST")

	certificate := fixture.issue(t, requestPath)
	request := parseCSRIssueRequest(t, requestDER)
	assertCSRIssueCertificateMatchesRequest(t, certificate, request)
	if !bytes.Equal(certificate.RawSubject, rawSubject) {
		t.Fatalf("certificate RawSubject = %x, want CSR RawSubject %x", certificate.RawSubject, rawSubject)
	}
	if certificate.Subject.CommonName != "" || !slices.Equal(certificate.Subject.Organization, []string{"npc"}) {
		t.Fatalf("certificate subject = %#v, want preserved non-CN subject", certificate.Subject)
	}
}

func TestCertCreateCSRReplacesOnlyExplicitIdentityCategories(t *testing.T) {
	t.Parallel()
	fixture := newCSRIssueFixture(t)
	requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "original.example", Organization: []string{"npc"}},
		DNSNames:    []string{"original.example", "alt.example"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")},
	})
	request := parseCSRIssueRequest(t, requestDER)
	requestPath := fixture.writeRequest(t, "overrides.csr", requestDER, "CERTIFICATE REQUEST")

	tests := []struct {
		name        string
		flags       []string
		wantSubject pkix.Name
		wantRaw     []byte
		wantDNS     []string
		wantIPs     []net.IP
	}{
		{
			name:        "subject",
			flags:       []string{"--subject", "CN=replaced.example"},
			wantSubject: pkix.Name{CommonName: "replaced.example"},
			wantDNS:     request.DNSNames,
			wantIPs:     request.IPAddresses,
		},
		{
			name:        "DNS",
			flags:       []string{"--dns", "new.example", "--dns", "other.example"},
			wantSubject: request.Subject,
			wantRaw:     request.RawSubject,
			wantDNS:     []string{"new.example", "other.example"},
			wantIPs:     request.IPAddresses,
		},
		{
			name:        "IP",
			flags:       []string{"--ip", "198.51.100.7"},
			wantSubject: request.Subject,
			wantRaw:     request.RawSubject,
			wantDNS:     request.DNSNames,
			wantIPs:     []net.IP{net.ParseIP("198.51.100.7")},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := fixture.issueArgs(requestPath)
			args = append(args, test.flags...)
			stdout, _, err := executeRootStreams(t, args...)
			require.NoError(t, err)
			certificate := parseCSRIssueCertificatePEM(t, []byte(stdout))
			if certificate.Subject.String() != test.wantSubject.String() {
				t.Fatalf("subject = %q, want %q", certificate.Subject, test.wantSubject)
			}
			if test.wantRaw != nil && !bytes.Equal(certificate.RawSubject, test.wantRaw) {
				t.Fatalf("RawSubject = %x, want %x", certificate.RawSubject, test.wantRaw)
			}
			if !slices.Equal(certificate.DNSNames, test.wantDNS) {
				t.Fatalf("DNS SANs = %v, want %v", certificate.DNSNames, test.wantDNS)
			}
			if !equalCSRIssueIPs(certificate.IPAddresses, test.wantIPs) {
				t.Fatalf("IP SANs = %v, want %v", certificate.IPAddresses, test.wantIPs)
			}
		})
	}
}

func TestCertCreateCSRIdentityRequirements(t *testing.T) {
	t.Parallel()
	fixture := newCSRIssueFixture(t)

	t.Run("SAN only", func(t *testing.T) {
		t.Parallel()
		requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{DNSNames: []string{"san-only.example"}})
		certificate := fixture.issue(t, fixture.writeRequest(t, "san-only.csr", requestDER, "CERTIFICATE REQUEST"))
		if len(certificate.Subject.Names) != 0 || len(certificate.DNSNames) != 1 || certificate.DNSNames[0] != "san-only.example" {
			t.Fatalf("SAN-only identity = subject:%#v DNS:%v", certificate.Subject, certificate.DNSNames)
		}
		for _, extension := range certificate.Extensions {
			if extension.Id.Equal(csrIssueOIDSubjectAltName) && !extension.Critical {
				t.Fatal("SAN extension is not critical for an empty subject")
			}
		}
	})

	t.Run("non-CN subject", func(t *testing.T) {
		t.Parallel()
		requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{Subject: pkix.Name{Organization: []string{"npc client"}}})
		certificate := fixture.issue(t, fixture.writeRequest(t, "organization.csr", requestDER, "CERTIFICATE REQUEST"))
		if certificate.Subject.CommonName != "" || !slices.Equal(certificate.Subject.Organization, []string{"npc client"}) {
			t.Fatalf("subject = %#v, want organization without CN", certificate.Subject)
		}
	})

	t.Run("empty identity", func(t *testing.T) {
		t.Parallel()
		requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{})
		requestPath := fixture.writeRequest(t, "empty.csr", requestDER, "CERTIFICATE REQUEST")
		err := assertCSRIssueFailurePreservesOutput(t, fixture.issueArgs(requestPath))
		message := strings.ToLower(err.Error())
		if !strings.Contains(message, "subject") && !strings.Contains(message, "identity") {
			t.Fatalf("error = %v, want empty identity failure", err)
		}
	})

	t.Run("empty identity with subject override", func(t *testing.T) {
		t.Parallel()
		requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{})
		requestPath := fixture.writeRequest(t, "empty-overridden.csr", requestDER, "CERTIFICATE REQUEST")
		args := append(fixture.issueArgs(requestPath), "--subject", "CN=overridden.example")
		stdout, _, err := executeRootStreams(t, args...)
		require.NoError(t, err)
		certificate := parseCSRIssueCertificatePEM(t, []byte(stdout))
		if certificate.Subject.CommonName != "overridden.example" || len(certificate.Subject.Names) != 1 {
			t.Fatalf("overridden subject = %#v", certificate.Subject)
		}
	})

	t.Run("no implicit SAN", func(t *testing.T) {
		t.Parallel()
		requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "no-san.example"}})
		certificate := fixture.issue(t, fixture.writeRequest(t, "no-san.csr", requestDER, "CERTIFICATE REQUEST"))
		if len(certificate.DNSNames) != 0 || len(certificate.IPAddresses) != 0 {
			t.Fatalf("certificate SANs = DNS:%v IP:%v, want none", certificate.DNSNames, certificate.IPAddresses)
		}
	})
}

func TestCertCreateCSRControlsLifetimeAndUsages(t *testing.T) {
	t.Parallel()
	fixture := newCSRIssueFixture(t)
	requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "usage.example"},
		DNSNames: []string{"usage.example"},
	})
	requestPath := fixture.writeRequest(t, "usage.csr", requestDER, "CERTIFICATE REQUEST")

	for _, test := range []struct {
		name      string
		flag      string
		wantUsage x509.ExtKeyUsage
	}{
		{name: "server", flag: "--server-only", wantUsage: x509.ExtKeyUsageServerAuth},
		{name: "client", flag: "--client-only", wantUsage: x509.ExtKeyUsageClientAuth},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			before := time.Now().UTC()
			args := append(fixture.issueArgs(requestPath), test.flag, "--days", "7")
			stdout, _, err := executeRootStreams(t, args...)
			require.NoError(t, err)
			certificate := parseCSRIssueCertificatePEM(t, []byte(stdout))
			if !slices.Equal(certificate.ExtKeyUsage, []x509.ExtKeyUsage{test.wantUsage}) {
				t.Fatalf("ExtKeyUsage = %v, want %v", certificate.ExtKeyUsage, test.wantUsage)
			}
			wantNotAfter := before.Truncate(time.Second).Add(7 * 24 * time.Hour)
			if delta := certificate.NotAfter.Sub(wantNotAfter); delta < -time.Second || delta > time.Second {
				t.Fatalf("NotAfter = %s, want approximately %s", certificate.NotAfter, wantNotAfter)
			}
		})
	}
}

func TestCertCreateCSRRejectsInvalidSelectionsBeforeOutput(t *testing.T) {
	t.Parallel()
	fixture := newCSRIssueFixture(t)
	requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf"}})
	requestPath := fixture.writeRequest(t, "selection.csr", requestDER, "CERTIFICATE REQUEST")
	keyPath := filepath.Join(t.TempDir(), "leaf.key")
	generateTestKey(t, "ed25519", keyPath)

	tests := []struct {
		name string
		want string
		args []string
	}{
		{name: "issuer required", args: []string{"cert", "create", "--csr", requestPath}, want: "issuer"},
		{name: "issuer certificate required", args: []string{"cert", "create", "--csr", requestPath, "--issuer-key", fixture.caKeyPath}, want: "issuer"},
		{name: "issuer key required", args: []string{"cert", "create", "--csr", requestPath, "--issuer-cert", fixture.caCertPath}, want: "issuer"},
		{name: "subject key conflict", args: append(fixture.issueArgs(requestPath), "--key", keyPath), want: "--key"},
		{name: "CA conflict", args: append(fixture.issueArgs(requestPath), "--ca"), want: "--ca"},
		{name: "empty DNS override", args: append(fixture.issueArgs(requestPath), "--dns="), want: "--dns"},
		{name: "empty IP override", args: append(fixture.issueArgs(requestPath), "--ip="), want: "--ip"},
		{name: "multiple stdin owners", args: []string{"cert", "create", "--csr", "-", "--issuer-cert", "-", "--issuer-key", fixture.caKeyPath}, want: "at most one"},
		{name: "unused input", args: append(fixture.issueArgs(requestPath), "--input", requestPath), want: "--input requires"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := assertCSRIssueFailurePreservesOutput(t, test.args)
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.want)) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestCertCreateCSRReadsEncodedStdinAndDER(t *testing.T) {
	t.Parallel()
	fixture := newCSRIssueFixture(t)
	requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "stdin.example"},
		DNSNames: []string{"stdin.example"},
	})

	t.Run("DER file", func(t *testing.T) {
		t.Parallel()
		path := fixture.writeDER(t, "request.der", requestDER)
		certificate := fixture.issue(t, path)
		assertCSRIssueCertificateMatchesRequest(t, certificate, parseCSRIssueRequest(t, requestDER))
	})

	t.Run("NEW CERTIFICATE REQUEST", func(t *testing.T) {
		t.Parallel()
		path := fixture.writeRequest(t, "new-request.pem", requestDER, "NEW CERTIFICATE REQUEST")
		certificate := fixture.issue(t, path)
		assertCSRIssueCertificateMatchesRequest(t, certificate, parseCSRIssueRequest(t, requestDER))
	})

	t.Run("base64 input", func(t *testing.T) {
		t.Parallel()
		encodedPath := filepath.Join(t.TempDir(), "request.b64")
		encoded := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER}))
		require.NoError(t, os.WriteFile(encodedPath, []byte(encoded), 0o600))
		args := fixture.issueArgs("-")
		args = append(args, "--input", encodedPath, "--input-encoding", "base64")
		stdout, _, err := executeRootStreams(t, args...)
		require.NoError(t, err)
		assertCSRIssueCertificateMatchesRequest(t, parseCSRIssueCertificatePEM(t, []byte(stdout)), parseCSRIssueRequest(t, requestDER))
	})

	t.Run("one-byte stdin", func(t *testing.T) {
		t.Parallel()
		requestPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER})
		stdout, _, err := executeRootStreamsWithInput(t, iotest.OneByteReader(bytes.NewReader(requestPEM)), fixture.issueArgs("-")...)
		require.NoError(t, err)
		assertCSRIssueCertificateMatchesRequest(t, parseCSRIssueCertificatePEM(t, []byte(stdout)), parseCSRIssueRequest(t, requestDER))
	})
}

func TestCertCreateCSRRejectsInvalidSignatureAndIssuer(t *testing.T) {
	t.Parallel()
	fixture := newCSRIssueFixture(t)
	requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf"}})

	t.Run("bad signature", func(t *testing.T) {
		t.Parallel()
		tampered := bytes.Clone(requestDER)
		tampered[len(tampered)-1] ^= 0x01
		request, err := x509.ParseCertificateRequest(tampered)
		require.NoError(t, err, "parse tampered CSR fixture: %v", err)
		if err := request.CheckSignature(); err == nil {
			t.Fatal("tampered CSR fixture retained a valid signature")
		}
		path := fixture.writeRequest(t, "bad-signature.csr", tampered, "CERTIFICATE REQUEST")
		err = assertCSRIssueFailurePreservesOutput(t, fixture.issueArgs(path))
		if !strings.Contains(strings.ToLower(err.Error()), "signature") {
			t.Fatalf("error = %v, want signature failure", err)
		}
	})

	t.Run("issuer key mismatch", func(t *testing.T) {
		t.Parallel()
		path := fixture.writeRequest(t, "mismatch.csr", requestDER, "CERTIFICATE REQUEST")
		wrongKey := filepath.Join(t.TempDir(), "wrong-ca.key")
		writeCSRIssuePrivateKey(t, wrongKey, mustCSRIssuePrivateKey(t))
		args := []string{"cert", "create", "--csr", path, "--issuer-cert", fixture.caCertPath, "--issuer-key", wrongKey}
		err := assertCSRIssueFailurePreservesOutput(t, args)
		require.ErrorIs(t, err, asym.ErrIssuerKeyMismatch, "error = %v, want ErrIssuerKeyMismatch", err)
	})

	t.Run("issuer is not a CA", func(t *testing.T) {
		t.Parallel()
		path := fixture.writeRequest(t, "non-ca.csr", requestDER, "CERTIFICATE REQUEST")
		issuerKey := mustCSRIssuePrivateKey(t)
		now := time.Now().UTC()
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(2),
			Subject:               pkix.Name{CommonName: "not-a-ca"},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(90 * 24 * time.Hour),
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageDigitalSignature,
		}
		issuerDER, err := x509.CreateCertificate(rand.Reader, template, template, issuerKey.Public(), issuerKey)
		require.NoError(t, err)
		dir := t.TempDir()
		issuerCertPath := filepath.Join(dir, "not-ca.pem")
		require.NoError(t, os.WriteFile(issuerCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER}), 0o600))
		issuerKeyPath := filepath.Join(dir, "not-ca-key.pem")
		writeCSRIssuePrivateKey(t, issuerKeyPath, issuerKey)
		args := []string{"cert", "create", "--csr", path, "--issuer-cert", issuerCertPath, "--issuer-key", issuerKeyPath}
		err = assertCSRIssueFailurePreservesOutput(t, args)
		require.ErrorIs(t, err, asym.ErrIssuerNotCA, "error = %v, want ErrIssuerNotCA", err)
	})

	t.Run("outlives issuer", func(t *testing.T) {
		t.Parallel()
		path := fixture.writeRequest(t, "outlive.csr", requestDER, "CERTIFICATE REQUEST")
		args := append(fixture.issueArgs(path), "--days", "401")
		err := assertCSRIssueFailurePreservesOutput(t, args)
		require.ErrorIs(t, err, asym.ErrIssuerValidity, "error = %v, want ErrIssuerValidity", err)
	})
}

func TestCertCreateCSRRejectsUnsupportedAndDuplicateExtensions(t *testing.T) {
	t.Parallel()
	fixture := newCSRIssueFixture(t)
	mailURI, err := url.Parse("spiffe://example.test/service")
	require.NoError(t, err)
	tests := []struct {
		name     string
		template *x509.CertificateRequest
		flags    []string
	}{
		{name: "email SAN", template: &x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf"}, EmailAddresses: []string{"ops@example.test"}}},
		{name: "URI SAN", template: &x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf"}, URIs: []*url.URL{mailURI}}},
		{
			name:     "email SAN despite DNS override",
			template: &x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf"}, DNSNames: []string{"old.example"}, EmailAddresses: []string{"ops@example.test"}},
			flags:    []string{"--dns", "new.example"},
		},
		{name: "unknown", template: requestWithCSRIssueExtension(csrIssueOIDUnsupported)},
		{name: "key usage", template: requestWithCSRIssueExtension(csrIssueOIDKeyUsage)},
		{name: "extended key usage", template: requestWithCSRIssueExtension(csrIssueOIDExtendedKeyUsage)},
		{
			name: "duplicate SAN",
			template: &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: "leaf"},
				ExtraExtensions: []pkix.Extension{
					{Id: csrIssueOIDSubjectAltName, Value: []byte{0x30, 0x00}},
					{Id: csrIssueOIDSubjectAltName, Value: []byte{0x30, 0x00}},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			requestDER := createCSRIssueRequest(t, test.template)
			path := fixture.writeRequest(t, strings.ReplaceAll(test.name, " ", "-")+".csr", requestDER, "CERTIFICATE REQUEST")
			args := append(fixture.issueArgs(path), test.flags...)
			err := assertCSRIssueFailurePreservesOutput(t, args)
			want := "unsupported"
			if test.name == "duplicate SAN" {
				want = "duplicate"
			}
			if !strings.Contains(strings.ToLower(err.Error()), want) {
				t.Fatalf("error = %v, want explicit %s extension error", err, want)
			}
		})
	}
}

func TestCertCreateCSRRejectsMalformedAndTrailingArtifacts(t *testing.T) {
	t.Parallel()
	fixture := newCSRIssueFixture(t)
	requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf"}})
	validPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER})
	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "truncated DER", data: requestDER[:len(requestDER)-1]},
		{name: "DER trailing", data: append(bytes.Clone(requestDER), 0x00)},
		{name: "wrong PEM type", data: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: requestDER})},
		{name: "garbage before PEM", data: append([]byte("garbage\n"), validPEM...)},
		{name: "garbage after PEM", data: append(bytes.Clone(validPEM), []byte("garbage\n")...)},
		{name: "multiple PEM blocks", data: append(bytes.Clone(validPEM), validPEM...)},
		{name: "truncated PEM", data: validPEM[:len(validPEM)-16]},
		{
			name: "malformed first PEM block",
			data: append([]byte("-----BEGIN CERTIFICATE REQUEST-----\n!\n-----END CERTIFICATE REQUEST-----\n"), validPEM...),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "request")
			require.NoError(t, os.WriteFile(path, test.data, 0o600))
			err := assertCSRIssueFailurePreservesOutput(t, fixture.issueArgs(path))
			message := strings.ToLower(err.Error())
			if !strings.Contains(message, "csr") && !strings.Contains(message, "certificate request") {
				t.Fatalf("error = %v, want CSR parse failure", err)
			}
		})
	}
}

func TestCertCreateCSRBoundsInputAtKeyArtifactLimit(t *testing.T) {
	t.Parallel()
	fixture := newCSRIssueFixture(t)
	requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "limit.example"}})
	requestPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER})
	if int64(len(requestPEM)) >= artifact.MaxKeyBytes {
		t.Fatalf("CSR fixture length = %d, want below %d", len(requestPEM), artifact.MaxKeyBytes)
	}
	exact := append(bytes.Repeat([]byte{'\n'}, int(artifact.MaxKeyBytes)-len(requestPEM)), requestPEM...)
	exactPath := filepath.Join(t.TempDir(), "exact.csr")
	require.NoError(t, os.WriteFile(exactPath, exact, 0o600))
	if _, _, err := executeRootStreams(t, fixture.issueArgs(exactPath)...); err != nil {
		t.Fatalf("exact %d-byte CSR input: %v", artifact.MaxKeyBytes, err)
	}

	over := bytes.NewReader(bytes.Repeat([]byte{'x'}, int(artifact.MaxKeyBytes)+2))
	stdout, _, err := executeRootStreamsWithInput(t, over, fixture.issueArgs("-")...)
	if !errors.Is(err, artifact.ErrTooLarge) || stdout != "" || over.Len() != 1 {
		t.Fatalf("over-limit input = remaining:%d stdout:%q error:%v", over.Len(), stdout, err)
	}
}

func TestCertCreateCSRProtectsSourceAliases(t *testing.T) {
	t.Parallel()
	fixture := newCSRIssueFixture(t)
	requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "alias.example"}})

	for _, aliasKind := range []string{"same path", "hard link", "symbolic link"} {
		t.Run(aliasKind, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			requestPath := filepath.Join(dir, "source.csr")
			want := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER})
			require.NoError(t, os.WriteFile(requestPath, want, 0o600))
			outputPath := requestPath
			switch aliasKind {
			case "hard link":
				outputPath = filepath.Join(dir, "hardlink.csr")
				if err := os.Link(requestPath, outputPath); err != nil {
					t.Fatal(err)
				}
			case "symbolic link":
				outputPath = filepath.Join(dir, "symlink.csr")
				if err := os.Symlink(requestPath, outputPath); err != nil {
					t.Fatal(err)
				}
			}
			args := append(fixture.issueArgs(requestPath), "--output", outputPath)
			_, _, err := executeRootStreams(t, args...)
			require.ErrorIs(t, err, errCertificatePathCollision, "error = %v, want errCertificatePathCollision", err)
			got, readErr := os.ReadFile(requestPath)
			require.NoError(t, readErr)
			if !bytes.Equal(got, want) {
				t.Fatal("CSR source was modified")
			}
		})
	}
}

type csrIssueFixture struct {
	ca         *x509.Certificate
	dir        string
	caCertPath string
	caKeyPath  string
}

func newCSRIssueFixture(tb testing.TB) csrIssueFixture {
	tb.Helper()
	dir := tb.TempDir()
	private := mustCSRIssuePrivateKey(tb)
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "csr-issue-test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(400 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
	if err != nil {
		tb.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	fixture := csrIssueFixture{
		dir:        dir,
		caCertPath: filepath.Join(dir, "ca.pem"),
		caKeyPath:  filepath.Join(dir, "ca-key.pem"),
		ca:         certificate,
	}
	if err := os.WriteFile(fixture.caCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		tb.Fatal(err)
	}
	writeCSRIssuePrivateKey(tb, fixture.caKeyPath, private)
	return fixture
}

func (fixture csrIssueFixture) issueArgs(requestPath string) []string {
	return []string{
		"cert", "create", "--csr", requestPath,
		"--issuer-cert", fixture.caCertPath,
		"--issuer-key", fixture.caKeyPath,
	}
}

func (fixture csrIssueFixture) issue(t *testing.T, requestPath string) *x509.Certificate {
	t.Helper()
	stdout, _, err := executeRootStreams(t, fixture.issueArgs(requestPath)...)
	require.NoError(t, err)
	return parseCSRIssueCertificatePEM(t, []byte(stdout))
}

func (fixture csrIssueFixture) writeRequest(t *testing.T, name string, der []byte, blockType string) string {
	t.Helper()
	path := filepath.Join(fixture.dir, name)
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600))
	return path
}

func (fixture csrIssueFixture) writeDER(t *testing.T, name string, der []byte) string {
	t.Helper()
	path := filepath.Join(fixture.dir, name)
	require.NoError(t, os.WriteFile(path, der, 0o600))
	return path
}

func mustCSRIssuePrivateKey(tb testing.TB) ed25519.PrivateKey {
	tb.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return private
}

func writeCSRIssuePrivateKey(tb testing.TB, path string, private ed25519.PrivateKey) {
	tb.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		tb.Fatal(err)
	}
}

func createCSRIssueRequest(tb testing.TB, template *x509.CertificateRequest) []byte {
	tb.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, template, mustCSRIssuePrivateKey(tb))
	if err != nil {
		tb.Fatal(err)
	}
	return der
}

func requestWithCSRIssueExtension(id asn1.ObjectIdentifier) *x509.CertificateRequest {
	return &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: "leaf"},
		ExtraExtensions: []pkix.Extension{{Id: id, Value: []byte{0x05, 0x00}}},
	}
}

func marshalCSRIssueRDNSequence(tb testing.TB, sequence pkix.RDNSequence) []byte {
	tb.Helper()
	raw, err := asn1.Marshal(sequence)
	if err != nil {
		tb.Fatal(err)
	}
	return raw
}

func parseCSRIssueRequest(tb testing.TB, der []byte) *x509.CertificateRequest {
	tb.Helper()
	request, err := x509.ParseCertificateRequest(der)
	if err != nil {
		tb.Fatal(err)
	}
	if err := request.CheckSignature(); err != nil {
		tb.Fatalf("check CSR fixture signature: %v", err)
	}
	return request
}

func parseCSRIssueCertificatePEM(tb testing.TB, data []byte) *x509.Certificate {
	tb.Helper()
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		tb.Fatalf("certificate PEM = block:%#v trailing:%q", block, rest)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		tb.Fatal(err)
	}
	return certificate
}

func assertCSRIssueCertificateMatchesRequest(tb testing.TB, certificate *x509.Certificate, request *x509.CertificateRequest) {
	tb.Helper()
	if !bytes.Equal(certificate.RawSubjectPublicKeyInfo, request.RawSubjectPublicKeyInfo) {
		tb.Fatalf("certificate public key = %x, want CSR public key %x", certificate.RawSubjectPublicKeyInfo, request.RawSubjectPublicKeyInfo)
	}
	if !bytes.Equal(certificate.RawSubject, request.RawSubject) {
		tb.Fatalf("certificate RawSubject = %x, want CSR RawSubject %x", certificate.RawSubject, request.RawSubject)
	}
	if !slices.Equal(certificate.DNSNames, request.DNSNames) || !equalCSRIssueIPs(certificate.IPAddresses, request.IPAddresses) {
		tb.Fatalf("certificate SANs = DNS:%v IP:%v, want DNS:%v IP:%v", certificate.DNSNames, certificate.IPAddresses, request.DNSNames, request.IPAddresses)
	}
}

func equalCSRIssueIPs(left, right []net.IP) bool {
	return slices.EqualFunc(left, right, func(left, right net.IP) bool { return left.Equal(right) })
}

func assertCSRIssueFailurePreservesOutput(t *testing.T, args []string) error {
	t.Helper()
	outputPath := filepath.Join(t.TempDir(), "certificate.pem")
	const preserved = "preserve existing output"
	require.NoError(t, os.WriteFile(outputPath, []byte(preserved), 0o640))
	args = append(slices.Clone(args), "--output", outputPath)
	stdout, _, runErr := executeRootStreams(t, args...)
	require.Error(t, runErr, "execute %v succeeded", args)
	if strings.Contains(runErr.Error(), "unknown flag: --csr") {
		t.Fatalf("execute %v did not recognize --csr: %v", args, runErr)
	}
	require.Empty(t, stdout, "stdout = %q, want empty", stdout)
	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	if string(data) != preserved {
		t.Fatalf("output = %q, want preserved content", data)
	}
	info, statErr := os.Stat(outputPath)
	require.NoError(t, statErr)
	require.Equal(t, os.FileMode(0o640), info.Mode().Perm(), "output mode = %04o, want 0640", info.Mode().Perm())
	return runErr
}
