package cert_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type csrIssuePublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type csrIssueTBSCertificateRequest struct { //nolint:govet // Field order is the signed PKCS #10 ASN.1 sequence.
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     csrIssuePublicKeyInfo
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type csrIssueRawCertificateRequest struct {
	Raw                asn1.RawContent
	TBS                csrIssueTBSCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

func TestCertCreateCSRAcceptsPEMMarkerInsideValidArtifactData(t *testing.T) {
	t.Parallel()
	fixture := newCSRIssueFixture(t)
	requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "identity-----BEGINmarker"},
	})
	request := parseCSRIssueRequest(t, requestDER)

	t.Run("DER subject", func(t *testing.T) {
		t.Parallel()
		path := fixture.writeDER(t, "der-marker.csr", requestDER)
		certificate := fixture.issue(t, path)
		assertCSRIssueCertificateMatchesRequest(t, certificate, request)
	})

	t.Run("PEM header", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "header-marker.csr")
		requestPEM := pem.EncodeToMemory(&pem.Block{
			Type:    "CERTIFICATE REQUEST",
			Headers: map[string]string{"Comment": "ordinary -----BEGIN marker"},
			Bytes:   requestDER,
		})
		require.NoError(t, os.WriteFile(path, requestPEM, 0o600))
		certificate := fixture.issue(t, path)
		assertCSRIssueCertificateMatchesRequest(t, certificate, request)
	})
}

func TestCertCreateCSRRejectsConstructedSANForms(t *testing.T) {
	t.Parallel()
	fixture := newCSRIssueFixture(t)
	tests := []struct {
		name  string
		value []byte
	}{
		{name: "DNS", value: []byte{0x30, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x61}},
		{name: "IP", value: []byte{0x30, 0x08, 0xa7, 0x06, 0x04, 0x04, 0xc0, 0x00, 0x02, 0x01}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if supportedCSRIssueSANOracle(test.value) {
				t.Fatal("fuzz oracle accepted a constructed SAN form")
			}
			requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: "constructed.example"},
				ExtraExtensions: []pkix.Extension{{
					Id:    csrIssueOIDSubjectAltName,
					Value: test.value,
				}},
			})
			path := fixture.writeRequest(t, strings.ToLower(test.name)+"-constructed.csr", requestDER, "CERTIFICATE REQUEST")
			err := assertCSRIssueFailurePreservesOutput(t, fixture.issueArgs(path))
			if !strings.Contains(strings.ToLower(err.Error()), "unsupported") {
				t.Fatalf("error = %v, want explicit unsupported SAN form", err)
			}
		})
	}
}

func TestCertCreateCSRRejectsMultipleExtensionRequestAttributeValues(t *testing.T) {
	t.Parallel()
	fixture := newCSRIssueFixture(t)
	extensionRequestOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	emptySAN := pkix.AttributeTypeAndValue{Type: csrIssueOIDSubjectAltName, Value: []byte{0x30, 0x00}}
	requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "duplicate-values.example"},
		Attributes: []pkix.AttributeTypeAndValueSET{{ //nolint:staticcheck // Only this legacy field can encode multiple extensionRequest SET values.
			Type:  extensionRequestOID,
			Value: [][]pkix.AttributeTypeAndValue{{emptySAN}, {emptySAN}},
		}},
	})
	request := parseCSRIssueRequest(t, requestDER)
	require.Len(t, request.Extensions, 1, "fixture parsed extensions = %d, want one visible extension and one ignored attribute value", len(request.Extensions))
	path := fixture.writeRequest(t, "duplicate-extension-values.csr", requestDER, "CERTIFICATE REQUEST")
	err := assertCSRIssueFailurePreservesOutput(t, fixture.issueArgs(path))
	if !strings.Contains(strings.ToLower(err.Error()), "extension") {
		t.Fatalf("error = %v, want explicit extension request ambiguity", err)
	}
}

func TestCertCreateCSRRejectsMalformedExtensionRequestAttribute(t *testing.T) {
	t.Parallel()
	fixture := newCSRIssueFixture(t)
	requestDER := createMalformedCSRIssueExtensionRequest(t)
	request := parseCSRIssueRequest(t, requestDER)
	require.Empty(t, request.Extensions, "fixture parsed extensions = %d, want malformed extension request hidden by standard parser", len(request.Extensions))
	path := fixture.writeRequest(t, "malformed-extension-request.csr", requestDER, "CERTIFICATE REQUEST")
	err := assertCSRIssueFailurePreservesOutput(t, fixture.issueArgs(path))
	if !strings.Contains(strings.ToLower(err.Error()), "extension") {
		t.Fatalf("error = %v, want explicit malformed extension request error", err)
	}
}

func TestCertCreateCSRRejectsEmptySANExtension(t *testing.T) {
	t.Parallel()
	fixture := newCSRIssueFixture(t)
	requestDER := createCSRIssueRequest(t, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "empty-san.example"},
		ExtraExtensions: []pkix.Extension{{
			Id:    csrIssueOIDSubjectAltName,
			Value: []byte{0x30, 0x00},
		}},
	})
	request := parseCSRIssueRequest(t, requestDER)
	require.Len(t, request.Extensions, 1, "fixture parsed extensions = %d, want visible empty SAN extension", len(request.Extensions))
	path := fixture.writeRequest(t, "empty-san.csr", requestDER, "CERTIFICATE REQUEST")
	err := assertCSRIssueFailurePreservesOutput(t, fixture.issueArgs(path))
	if !strings.Contains(strings.ToLower(err.Error()), "extension") && !strings.Contains(strings.ToLower(err.Error()), "san") {
		t.Fatalf("error = %v, want explicit empty SAN extension error", err)
	}
}

func createMalformedCSRIssueExtensionRequest(tb testing.TB) []byte {
	tb.Helper()
	private := mustCSRIssuePrivateKey(tb)
	base, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "malformed-extension.example"},
	}, private)
	if err != nil {
		tb.Fatal(err)
	}
	var request csrIssueRawCertificateRequest
	rest, err := asn1.Unmarshal(base, &request)
	if err != nil || len(rest) != 0 {
		tb.Fatalf("parse base CSR: err=%v trailing=%d", err, len(rest))
	}
	attributeDER, err := asn1.Marshal(struct {
		ID       asn1.ObjectIdentifier
		WrongTag []byte
	}{
		ID:       asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14},
		WrongTag: []byte{0x30, 0x00},
	})
	if err != nil {
		tb.Fatal(err)
	}
	var attribute asn1.RawValue
	rest, err = asn1.Unmarshal(attributeDER, &attribute)
	if err != nil || len(rest) != 0 {
		tb.Fatalf("parse malformed attribute fixture: err=%v trailing=%d", err, len(rest))
	}
	request.Raw = nil
	request.TBS.Raw = nil
	request.TBS.RawAttributes = []asn1.RawValue{attribute}
	tbsDER, err := asn1.Marshal(request.TBS)
	if err != nil {
		tb.Fatal(err)
	}
	request.TBS.Raw = tbsDER
	signature := ed25519.Sign(private, tbsDER)
	request.SignatureValue = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	der, err := asn1.Marshal(request)
	if err != nil {
		tb.Fatal(err)
	}
	return der
}
