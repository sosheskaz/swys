package cert_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/artifact"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
)

const (
	certTestDNSName = "service.example"
	certTestRFC3339 = time.RFC3339
)

var certTestCurrentTime = time.Date(2026, time.January, 2, 15, 4, 5, 0, time.UTC)

type certFixtureOptions struct { //nolint:govet // semantic grouping makes fixture options easier to audit
	leafKey               crypto.Signer
	extKeyUsage           []x509.ExtKeyUsage
	dnsNames              []string
	ipAddresses           []net.IP
	extraExtensions       []pkix.Extension
	issuingCertificateURL []string
	ocspServer            []string
	crlDistributionPoints []string
	leafNotBefore         time.Time
	leafNotAfter          time.Time
	intermediateKeyUsage  x509.KeyUsage
	rootMaxPathLenZero    bool
	intermediateIsCA      bool
}

type certVerifyMatchFixture struct {
	root            *x509.Certificate
	intermediate    *x509.Certificate
	leaf            *x509.Certificate
	rootPEM         []byte
	intermediatePEM []byte
	leafPEM         []byte
	leafDER         []byte
	leafKey         crypto.Signer
	leafKeyPKCS8PEM []byte
	leafCSRDER      []byte
	leafCSRPEM      []byte
}

func TestCertVerifyTrustChainAndDERInputs(t *testing.T) {
	t.Parallel()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{})
	wrong := newCertVerifyMatchFixture(t, certFixtureOptions{})
	dir := t.TempDir()
	leafPath := writeCertTestFile(t, dir, "leaf.pem", fixture.leafPEM)
	leafDERPath := writeCertTestFile(t, dir, "leaf.der", fixture.leafDER)
	chainPath := writeCertTestFile(t, dir, "chain.pem", fixture.leafPEM, fixture.intermediatePEM)
	fullchainPath := writeCertTestFile(t, dir, "fullchain.pem", fixture.leafPEM, fixture.intermediatePEM, fixture.rootPEM)
	reversedPath := writeCertTestFile(t, dir, "reversed.pem", fixture.intermediatePEM, fixture.leafPEM)
	rootPath := writeCertTestFile(t, dir, "root.pem", fixture.rootPEM)
	intermediatePath := writeCertTestFile(t, dir, "intermediate.pem", fixture.intermediatePEM)
	wrongRootPath := writeCertTestFile(t, dir, "wrong-root.pem", wrong.rootPEM)

	positive := [][]string{
		{"--input", chainPath, "--ca", rootPath},
		{"--input", leafPath, "--intermediates", intermediatePath, "--ca", rootPath},
		{"--input", leafDERPath, "--intermediates", intermediatePath, "--ca", rootPath},
		{"--input", chainPath, "--ca", rootPath, "--system-ca"},
	}
	for _, testArgs := range positive {
		args := append([]string{"cert", "verify"}, testArgs...)
		args = append(args, "--at", certTestCurrentTime.Format(certTestRFC3339), "--format", "json")
		stdout, stderr, err := executeRootStreams(t, args...)
		if err != nil {
			t.Errorf("%v: %v (stderr %q)", args, err, stderr)
			continue
		}
		assertCertBooleanReport(t, stdout, "verified", true)
	}

	negative := [][]string{
		{"--input", chainPath, "--ca", wrongRootPath},
		{"--input", leafPath, "--ca", rootPath},
		{"--input", chainPath},
		{"--input", fullchainPath},
		{"--input", chainPath, "--intermediates", rootPath},
		{"--input", fixturePath(t, dir, "self-signed.pem", fixture.rootPEM)},
		{"--input", leafPath, "--intermediates", rootPath, "--ca", rootPath},
	}
	for _, testArgs := range negative {
		args := append([]string{"cert", "verify"}, testArgs...)
		args = append(args, "--at", certTestCurrentTime.Format(certTestRFC3339), "--format", "json")
		stdout, _, err := executeRootStreams(t, args...)
		if err == nil {
			t.Errorf("%v: want nonzero result", args)
			continue
		}
		assertCertBooleanReport(t, stdout, "verified", false)
		assertNoPrivateKeyMaterial(t, stdout)
	}
	reversedOutput := fixturePath(t, dir, "reversed.out", []byte("preserve"))
	_, _, err := executeRootStreams(t,
		"cert", "verify", "--input", reversedPath, "--ca", rootPath,
		"--at", certTestCurrentTime.Format(certTestRFC3339), "--format", "json", "--output", reversedOutput,
	)
	require.ErrorIs(t, err, errCertificateReportNegative, "non-leaf-first chain error = %v, want completed negative report", err)
	data, readErr := os.ReadFile(reversedOutput)
	require.NoError(t, readErr)
	if string(data) == "preserve" {
		t.Fatal("non-leaf-first completed report did not replace output")
	}
	assertCertBooleanReport(t, string(data), "verified", false)
	assertCertReportValidPiecesWrongOrder(t, string(data))
}

func TestCertVerifyReadsCustomRootsFromStdin(t *testing.T) {
	t.Parallel()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{})
	dir := t.TempDir()
	chainPath := writeCertTestFile(t, dir, "chain.pem", fixture.leafPEM, fixture.intermediatePEM)

	for _, test := range []struct {
		name string
		root []byte
	}{
		{name: "PEM", root: fixture.rootPEM},
		{name: "DER", root: fixture.root.Raw},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			stdout, stderr, err := executeRootStreamsWithInput(
				t,
				bytes.NewReader(test.root),
				"cert", "verify", "--input", chainPath, "--ca", "-",
				"--at", certTestCurrentTime.Format(certTestRFC3339), "--format", "json",
			)
			require.NoError(t, err, "npc cert verify with %s CA on stdin: %v (stderr %q)", test.name, err, stderr)
			assertCertBooleanReport(t, stdout, "verified", true)
		})
	}

	t.Run("encoded main file with raw CA stdin", func(t *testing.T) {
		t.Parallel()
		encodedChain := base64.StdEncoding.EncodeToString(append(bytes.Clone(fixture.leafPEM), fixture.intermediatePEM...))
		encodedPath := writeCertTestFile(t, t.TempDir(), "chain.b64", []byte(encodedChain))
		stdout, stderr, err := executeRootStreamsWithInput(t, bytes.NewReader(fixture.rootPEM),
			"cert", "verify", "--input", encodedPath, "--input-encoding", "base64", "--ca", "-",
			"--at", certTestCurrentTime.Format(certTestRFC3339), "--format", "json",
		)
		require.NoError(t, err, "encoded main with raw CA stdin: stderr %q", stderr)
		assertCertBooleanReport(t, stdout, "verified", true)
	})
}

func TestCertVerifyRejectsMultipleStdinSourcesBeforeIO(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "default chain stdin", args: []string{"cert", "verify", "--ca", "-"}},
		{name: "explicit chain stdin", args: []string{"cert", "verify", "--input", "-", "--ca", "-"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			outputPath := fixturePath(t, t.TempDir(), "report.json", []byte("preserve"))
			root := newRootCmd()
			input := &certVerifyReadCounter{}
			root.SetIn(input)
			_, _, err := executeRootCommandStreams(t, root, append(test.args, "--output", outputPath)...)
			require.ErrorIs(t, err, errCertificateInputSelection, "error = %v, want errCertificateInputSelection", err)
			if reads := input.count.Load(); reads != 0 {
				t.Fatalf("invalid stdin selection read stdin %d times", reads)
			}
			data, readErr := os.ReadFile(outputPath)
			if readErr != nil || string(data) != "preserve" {
				t.Fatalf("invalid stdin selection changed output: data=%q err=%v", data, readErr)
			}
		})
	}
}

func TestCertVerifyCAStdinRejectsMalformedAndOversizedDataBeforeOutput(t *testing.T) {
	t.Parallel()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{})
	dir := t.TempDir()
	chainPath := writeCertTestFile(t, dir, "chain.pem", fixture.leafPEM, fixture.intermediatePEM)

	for _, test := range []struct {
		wantErr error
		name    string
		input   []byte
	}{
		{name: "invalid", input: []byte("not a certificate")},
		{name: "trailing data", input: append(bytes.Clone(fixture.rootPEM), []byte("trailing data")...), wantErr: errTrailingCertificateData},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			outputPath := fixturePath(t, t.TempDir(), "report.json", []byte("preserve"))
			stdout, _, err := executeRootStreamsWithInput(
				t,
				bytes.NewReader(test.input),
				"cert", "verify", "--input", chainPath, "--ca", "-", "--output", outputPath,
			)
			if err == nil || errors.Is(err, os.ErrNotExist) || test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("stdout = %q, error = %v, want CA parse error %v", stdout, err, test.wantErr)
			}
			data, readErr := os.ReadFile(outputPath)
			if readErr != nil || string(data) != "preserve" {
				t.Fatalf("invalid CA stdin changed output: data=%q err=%v", data, readErr)
			}
		})
	}

	t.Run("size limit", func(t *testing.T) {
		t.Parallel()
		input := bytes.NewReader(bytes.Repeat([]byte{'x'}, int(artifact.MaxCertificateBytes)+2))
		outputPath := fixturePath(t, t.TempDir(), "report.json", []byte("preserve"))
		stdout, _, err := executeRootStreamsWithInput(
			t,
			input,
			"cert", "verify", "--input", chainPath, "--ca", "-", "--output", outputPath,
		)
		if !errors.Is(err, artifact.ErrTooLarge) || input.Len() != 1 || stdout != "" {
			t.Fatalf("remaining = %d, stdout = %q, error = %v; want bounded CA stdin rejection", input.Len(), stdout, err)
		}
		data, readErr := os.ReadFile(outputPath)
		if readErr != nil || string(data) != "preserve" {
			t.Fatalf("oversized CA stdin changed output: data=%q err=%v", data, readErr)
		}
	})
}

var errUnexpectedCertVerifyStdinRead = errors.New("unexpected certificate verification stdin read")

type certVerifyReadCounter struct{ count atomic.Int64 }

func (reader *certVerifyReadCounter) Read([]byte) (int, error) {
	reader.count.Add(1)
	return 0, errUnexpectedCertVerifyStdinRead
}

func TestCertVerifyCAFirstChainsAreCompletedNegativeReports(t *testing.T) {
	t.Parallel()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{})
	dir := t.TempDir()
	rootPath := writeCertTestFile(t, dir, "root.pem", fixture.rootPEM)
	chainPath := writeCertTestFile(t, dir, "root-root-leaf.pem", fixture.rootPEM, fixture.rootPEM, fixture.leafPEM)
	outputPath := fixturePath(t, dir, "report.json", []byte("preserve"))

	_, _, err := executeRootStreams(t,
		"cert", "verify", "--input", chainPath, "--ca", rootPath,
		"--at", certTestCurrentTime.Format(certTestRFC3339), "--format", "json", "--output", outputPath,
	)
	require.ErrorIs(t, err, errCertificateReportNegative, "root-root-leaf error = %v, want completed negative report", err)
	data, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	assertCertBooleanReport(t, string(data), "verified", false)
	assertCertReportDetailsIdentifyLink(t, string(data), 2, 3)
}

func TestCertVerifySameNameCAFirstChainCannotVerifyFirstCertificateOnly(t *testing.T) {
	t.Parallel()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{})
	dir := t.TempDir()
	rootPath := writeCertTestFile(t, dir, "trusted-root.pem", fixture.rootPEM)
	chainPath := writeCertTestFile(t, dir, "same-name-root-root-leaf.pem", certTestSameNameCAFirstChain(t, fixture.root))

	stdout, _, err := executeRootStreams(t,
		"cert", "verify", "--input", chainPath, "--ca", rootPath,
		"--at", certTestCurrentTime.Format(certTestRFC3339), "--format", "json",
	)
	require.ErrorIs(t, err, errCertificateReportNegative, "same-name CA-first chain error = %v, want completed negative report", err)
	assertCertBooleanReport(t, stdout, "verified", false)
	assertCertReportDetailsIdentifyLink(t, stdout, 1, 2)
}

func TestCertVerifyCompleteValidChainWrongOrderDiagnostic(t *testing.T) {
	t.Parallel()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{})
	if err := certTestVerifyOrderedFixture(fixture, certTestCurrentTime); err != nil {
		t.Fatalf("ordered fixture verification oracle: %v", err)
	}
	dir := t.TempDir()
	rootPath := writeCertTestFile(t, dir, "root.pem", fixture.rootPEM)
	reversedPath := writeCertTestFile(t, dir, "root-intermediate-leaf.pem", fixture.rootPEM, fixture.intermediatePEM, fixture.leafPEM)

	stdout, _, err := executeRootStreams(t,
		"cert", "verify", "--input", reversedPath, "--ca", rootPath,
		"--at", certTestCurrentTime.Format(certTestRFC3339), "--format", "json",
	)
	require.ErrorIs(t, err, errCertificateReportNegative, "valid pieces in wrong order error = %v, want completed negative report", err)
	assertCertBooleanReport(t, stdout, "verified", false)
	assertCertReportValidPiecesWrongOrder(t, stdout)
}

func TestCertVerifyMissingSuppliedIntermediateIsNotWrongOrder(t *testing.T) {
	t.Parallel()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{})
	roots := x509.NewCertPool()
	roots.AddCert(fixture.root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(fixture.intermediate)
	if _, err := fixture.leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		CurrentTime: certTestCurrentTime,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("complete fixture verification oracle: %v", err)
	}
	if bytes.Equal(fixture.leaf.RawIssuer, fixture.root.RawSubject) || fixture.leaf.CheckSignatureFrom(fixture.root) == nil {
		t.Fatal("fixture leaf is directly issued by root; missing-intermediate scenario is invalid")
	}

	dir := t.TempDir()
	rootPath := writeCertTestFile(t, dir, "root.pem", fixture.rootPEM)
	intermediatePath := writeCertTestFile(t, dir, "intermediate.pem", fixture.intermediatePEM)
	gappedPath := writeCertTestFile(t, dir, "leaf-root.pem", fixture.leafPEM, fixture.rootPEM)
	stdout, _, err := executeRootStreams(t,
		"cert", "verify", "--input", gappedPath, "--intermediates", intermediatePath, "--ca", rootPath,
		"--at", certTestCurrentTime.Format(certTestRFC3339), "--format", "json",
	)
	require.ErrorIs(t, err, errCertificateReportNegative, "gapped supplied chain error = %v, want completed negative report", err)
	assertCertBooleanReport(t, stdout, "verified", false)
	assertCertReportDetailsIdentifyLink(t, stdout, 1, 2)
	details := strings.ToLower(certTestReportDetails(t, stdout))
	if certTestClaimsAllPiecesValid(details) {
		t.Fatalf("details falsely diagnose missing intermediate as a reorderable valid chain: %q", details)
	}
}

func TestCertVerifyWrongOrderDoesNotHideInvalidCertificates(t *testing.T) {
	t.Parallel()
	expired := newCertVerifyMatchFixture(t, certFixtureOptions{
		leafNotBefore: certTestCurrentTime.Add(-72 * time.Hour),
		leafNotAfter:  certTestCurrentTime.Add(-48 * time.Hour),
	})
	var invalidError x509.CertificateInvalidError
	if err := certTestVerifyOrderedFixture(expired, certTestCurrentTime); !errors.As(err, &invalidError) || invalidError.Reason != x509.Expired {
		t.Fatalf("expired fixture oracle error = %v, want x509.Expired", err)
	}

	badSignature := newCertVerifyMatchFixture(t, certFixtureOptions{})
	badSignatureDER := bytes.Clone(badSignature.leafDER)
	badSignatureDER[len(badSignatureDER)-1] ^= 1
	badSignatureLeaf := certTestParseCertificate(t, badSignatureDER)
	if err := badSignatureLeaf.CheckSignatureFrom(badSignature.intermediate); err == nil {
		t.Fatal("signature-corrupted fixture still verifies against its intermediate")
	}

	tests := []struct { //nolint:govet // semantic grouping keeps diagnostic fixtures readable
		name       string
		fixture    *certVerifyMatchFixture
		leafPEM    []byte
		wantDetail string
	}{
		{name: "expired", fixture: expired, leafPEM: expired.leafPEM, wantDetail: "expired"},
		{
			name: "bad signature", fixture: badSignature,
			leafPEM:    pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: badSignatureDER}),
			wantDetail: "signature",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			rootPath := writeCertTestFile(t, dir, "root.pem", test.fixture.rootPEM)
			wrongOrderPath := writeCertTestFile(t, dir, "wrong-order.pem", test.fixture.rootPEM, test.fixture.intermediatePEM, test.leafPEM)
			stdout, _, err := executeRootStreams(t,
				"cert", "verify", "--input", wrongOrderPath, "--ca", rootPath,
				"--at", certTestCurrentTime.Format(certTestRFC3339), "--format", "json",
			)
			require.ErrorIs(t, err, errCertificateReportNegative, "wrong-order invalid chain error = %v, want completed negative report", err)
			assertCertBooleanReport(t, stdout, "verified", false)
			details := strings.ToLower(certTestReportDetails(t, stdout))
			if !strings.Contains(details, test.wantDetail) {
				t.Fatalf("details = %q, want %q defect", details, test.wantDetail)
			}
			if certTestClaimsAllPiecesValid(details) {
				t.Fatalf("details falsely claim invalid pieces form a valid chain: %q", details)
			}
		})
	}
}

func TestCertVerifyOrderedSignatureAndCAFailuresAreCompletedNegativeReports(t *testing.T) {
	t.Parallel()
	badSignature := newCertVerifyMatchFixture(t, certFixtureOptions{})
	badSignatureDER := bytes.Clone(badSignature.leafDER)
	badSignatureDER[len(badSignatureDER)-1] ^= 1
	if _, err := x509.ParseCertificate(badSignatureDER); err != nil {
		t.Fatalf("parse signature-corrupted fixture: %v", err)
	}
	invalidCA := newCertVerifyMatchFixture(t, certFixtureOptions{
		intermediateIsCA:     false,
		intermediateKeyUsage: x509.KeyUsageDigitalSignature,
	})

	tests := []struct {
		name    string
		fixture *certVerifyMatchFixture
		leafPEM []byte
	}{
		{name: "bad adjacent signature", fixture: badSignature, leafPEM: pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: badSignatureDER})},
		{name: "intermediate is not CA", fixture: invalidCA, leafPEM: invalidCA.leafPEM},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			rootPath := writeCertTestFile(t, dir, "root.pem", test.fixture.rootPEM)
			chainPath := writeCertTestFile(t, dir, "chain.pem", test.leafPEM, test.fixture.intermediatePEM)
			outputPath := fixturePath(t, dir, "report.json", []byte("preserve"))
			_, _, err := executeRootStreams(t,
				"cert", "verify", "--input", chainPath, "--ca", rootPath,
				"--at", certTestCurrentTime.Format(certTestRFC3339), "--format", "json", "--output", outputPath,
			)
			require.ErrorIs(t, err, errCertificateReportNegative, "error = %v, want completed negative report", err)
			data, readErr := os.ReadFile(outputPath)
			require.NoError(t, readErr)
			assertCertBooleanReport(t, string(data), "verified", false)
		})
	}
}

func TestCertVerifyPurposeHostnameTimeAndConstraints(t *testing.T) {
	t.Parallel()
	server := newCertVerifyMatchFixture(t, certFixtureOptions{})
	client := newCertVerifyMatchFixture(t, certFixtureOptions{extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	pathLimited := newCertVerifyMatchFixture(t, certFixtureOptions{rootMaxPathLenZero: true})
	invalidIntermediate := newCertVerifyMatchFixture(t, certFixtureOptions{
		intermediateIsCA:     false,
		intermediateKeyUsage: x509.KeyUsageDigitalSignature,
	})
	critical := newCertVerifyMatchFixture(t, certFixtureOptions{extraExtensions: []pkix.Extension{{
		Id: []int{1, 2, 3, 4, 5}, Critical: true, Value: []byte{5, 0},
	}}})
	dir := t.TempDir()

	tests := []struct {
		name     string
		fixture  *certVerifyMatchFixture
		extra    []string
		verified bool
	}{
		{name: "server purpose default", fixture: server, verified: true},
		{name: "server purpose explicit", fixture: server, extra: []string{"--purpose", "server"}, verified: true},
		{name: "client purpose rejects server EKU", fixture: server, extra: []string{"--purpose", "client"}},
		{name: "any purpose accepts server EKU", fixture: server, extra: []string{"--purpose", "any"}, verified: true},
		{name: "client purpose", fixture: client, extra: []string{"--purpose", "client"}, verified: true},
		{name: "DNS SAN", fixture: server, extra: []string{"--hostname", certTestDNSName}, verified: true},
		{name: "wrong DNS SAN", fixture: server, extra: []string{"--hostname", "wrong.example"}},
		{name: "IP SAN", fixture: server, extra: []string{"--hostname", "192.0.2.10"}, verified: true},
		{name: "wrong IP SAN", fixture: server, extra: []string{"--hostname", "192.0.2.11"}},
		{name: "before validity", fixture: server, extra: []string{"--at", server.leaf.NotBefore.Add(-time.Second).Format(certTestRFC3339)}},
		{name: "after validity", fixture: server, extra: []string{"--at", server.leaf.NotAfter.Add(time.Second).Format(certTestRFC3339)}},
		{name: "path constraint", fixture: pathLimited},
		{name: "intermediate CA constraint", fixture: invalidIntermediate},
		{name: "unhandled critical extension", fixture: critical},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			chainPath := writeCertTestFile(t, dir, strings.ReplaceAll(test.name, " ", "-")+"-chain.pem", test.fixture.leafPEM, test.fixture.intermediatePEM)
			rootPath := writeCertTestFile(t, dir, strings.ReplaceAll(test.name, " ", "-")+"-root.pem", test.fixture.rootPEM)
			args := []string{"cert", "verify", "--input", chainPath, "--ca", rootPath, "--format", "json"}
			if !slices.Contains(test.extra, "--at") {
				args = append(args, "--at", certTestCurrentTime.Format(certTestRFC3339))
			}
			args = append(args, test.extra...)
			stdout, _, err := executeRootStreams(t, args...)
			if test.verified {
				require.NoError(t, err, "error = %v, want verified", err)
				assertCertBooleanReport(t, stdout, "verified", true)
				return
			}
			if err == nil {
				t.Fatal("error = nil, want nonzero negative verification")
			}
			assertCertBooleanReport(t, stdout, "verified", false)
		})
	}
}

func TestCertVerifyReportsAndOutputPreservation(t *testing.T) {
	t.Parallel()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{})
	wrong := newCertVerifyMatchFixture(t, certFixtureOptions{})
	dir := t.TempDir()
	chainPath := writeCertTestFile(t, dir, "chain.pem", fixture.leafPEM, fixture.intermediatePEM)
	wrongRootPath := writeCertTestFile(t, dir, "wrong-root.pem", wrong.rootPEM)
	malformedPath := writeCertTestFile(t, dir, "malformed.pem", []byte("not a certificate"))

	stdout, _, err := executeRootStreams(t, "cert", "verify", "--input", chainPath, "--ca", wrongRootPath, "--at", certTestCurrentTime.Format(certTestRFC3339))
	if err == nil {
		t.Fatal("negative verification returned success")
	}
	if lower := strings.ToLower(stdout); !strings.Contains(lower, "verified") || !strings.Contains(lower, "false") {
		t.Fatalf("text report = %q, want completed negative verification", stdout)
	}
	assertNoPrivateKeyMaterial(t, stdout)

	negativeOutput := fixturePath(t, dir, "negative.out", []byte("preserve"))
	_, _, err = executeRootStreams(t,
		"cert", "verify", "--input", chainPath, "--ca", wrongRootPath,
		"--at", certTestCurrentTime.Format(certTestRFC3339), "--output", negativeOutput,
	)
	if err == nil {
		t.Fatal("negative verification returned success")
	}
	if data, readErr := os.ReadFile(negativeOutput); readErr != nil || string(data) == "preserve" {
		t.Fatalf("completed negative report did not replace output: data=%q err=%v", data, readErr)
	}

	malformedOutput := fixturePath(t, dir, "malformed.out", []byte("preserve"))
	_, _, err = executeRootStreams(t, "cert", "verify", "--input", malformedPath, "--output", malformedOutput)
	if err == nil {
		t.Fatal("malformed certificate returned success")
	}
	if data, readErr := os.ReadFile(malformedOutput); readErr != nil || string(data) != "preserve" {
		t.Fatalf("malformed input changed output: data=%q err=%v", data, readErr)
	}
}

func TestCertVerifyDefaultsToCurrentTimeAndRejectsInvalidAt(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{
		leafNotBefore: now.Add(-time.Hour),
		leafNotAfter:  now.Add(time.Hour),
	})
	dir := t.TempDir()
	chainPath := writeCertTestFile(t, dir, "chain.pem", fixture.leafPEM, fixture.intermediatePEM)
	rootPath := writeCertTestFile(t, dir, "root.pem", fixture.rootPEM)
	stdout, _, err := executeRootStreams(t, "cert", "verify", "--input", chainPath, "--ca", rootPath, "--format", "json")
	require.NoError(t, err, "default current time: %v", err)
	assertCertBooleanReport(t, stdout, "verified", true)

	outputPath := fixturePath(t, dir, "invalid-at.out", []byte("preserve"))
	_, _, err = executeRootStreams(t, "cert", "verify", "--input", chainPath, "--ca", rootPath, "--at", "not-rfc3339", "--output", outputPath)
	if err == nil {
		t.Fatal("invalid --at returned success")
	}
	if data, readErr := os.ReadFile(outputPath); readErr != nil || string(data) != "preserve" {
		t.Fatalf("invalid --at changed output: data=%q err=%v", data, readErr)
	}
}

func TestCertVerifyDoesNotFetchChainOCSPOrCRL(t *testing.T) {
	t.Parallel()
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{
		issuingCertificateURL: []string{server.URL + "/issuer"},
		ocspServer:            []string{server.URL + "/ocsp"},
		crlDistributionPoints: []string{server.URL + "/crl"},
	})
	dir := t.TempDir()
	rootPath := writeCertTestFile(t, dir, "root.pem", fixture.rootPEM)
	chainPath := writeCertTestFile(t, dir, "chain.pem", fixture.leafPEM, fixture.intermediatePEM)
	leafPath := writeCertTestFile(t, dir, "leaf.pem", fixture.leafPEM)

	stdout, _, err := executeRootStreams(t,
		"cert", "verify", "--input", chainPath, "--ca", rootPath,
		"--at", certTestCurrentTime.Format(certTestRFC3339), "--format", "json",
	)
	require.NoError(t, err, "local complete chain: %v", err)
	assertCertBooleanReport(t, stdout, "verified", true)
	stdout, _, err = executeRootStreams(t,
		"cert", "verify", "--input", leafPath, "--ca", rootPath,
		"--at", certTestCurrentTime.Format(certTestRFC3339), "--format", "json",
	)
	if err == nil {
		t.Fatal("missing intermediate unexpectedly verified")
	}
	assertCertBooleanReport(t, stdout, "verified", false)
	if got := requests.Load(); got != 0 {
		t.Fatalf("certificate verification made %d HTTP fetches, want 0", got)
	}
}

func TestCertMatchEveryOperandCombination(t *testing.T) {
	t.Parallel()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{})
	dir := t.TempDir()
	certPath := writeCertTestFile(t, dir, "cert.pem", fixture.leafPEM)
	keyPath := writeCertTestFile(t, dir, "key.pem", fixture.leafKeyPKCS8PEM)
	csrPath := writeCertTestFile(t, dir, "request.pem", fixture.leafCSRPEM)

	tests := []struct {
		name string
		args []string
	}{
		{name: "certificate and key", args: []string{"--cert", certPath, "--key", keyPath}},
		{name: "certificate and CSR", args: []string{"--cert", certPath, "--csr", csrPath}},
		{name: "key and CSR", args: []string{"--key", keyPath, "--csr", csrPath}},
		{name: "all three", args: []string{"--cert", certPath, "--key", keyPath, "--csr", csrPath}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := append([]string{"cert", "match"}, test.args...)
			args = append(args, "--format", "json")
			stdout, stderr, err := executeRootStreams(t, args...)
			require.NoError(t, err, "npc cert match: %v (stderr %q)", err, stderr)
			assertCertBooleanReport(t, stdout, "match", true)
			assertCertReportPublicDetails(t, stdout)
		})
	}
}

func TestCertMatchKeyFamiliesAndContainers(t *testing.T) {
	t.Parallel()
	_, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ecPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct { //nolint:govet // named fields keep the key-family table readable
		name   string
		signer crypto.Signer
		keys   func(testing.TB, crypto.Signer) [][]byte
	}{
		{name: "Ed25519", signer: edPrivate, keys: certTestGeneralKeyContainers},
		{name: "ECDSA", signer: ecPrivate, keys: certTestECDSAKeyContainers},
		{name: "RSA", signer: rsaPrivate, keys: certTestRSAKeyContainers},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newCertVerifyMatchFixture(t, certFixtureOptions{leafKey: test.signer})
			dir := t.TempDir()
			certPEMPath := writeCertTestFile(t, dir, "cert.pem", fixture.leafPEM)
			certDERPath := writeCertTestFile(t, dir, "cert.der", fixture.leafDER)
			csrPEMPath := writeCertTestFile(t, dir, "request.pem", fixture.leafCSRPEM)
			csrDERPath := writeCertTestFile(t, dir, "request.der", fixture.leafCSRDER)
			for index, keyBytes := range test.keys(t, test.signer) {
				keyPath := writeCertTestFile(t, dir, fmt.Sprintf("key-%d", index), keyBytes)
				certPath := []string{certPEMPath, certDERPath}[index%2]
				csrPath := []string{csrPEMPath, csrDERPath}[index%2]
				stdout, _, runErr := executeRootStreams(t, "cert", "match", "--cert", certPath, "--key", keyPath, "--csr", csrPath, "--format", "json")
				if runErr != nil {
					t.Errorf("container %d: %v", index, runErr)
					continue
				}
				assertCertBooleanReport(t, stdout, "match", true)
			}
		})
	}
}

func TestCertMatchBundleSignatureAndSemanticBoundaries(t *testing.T) {
	t.Parallel()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{
		leafNotBefore: certTestCurrentTime.Add(-72 * time.Hour),
		leafNotAfter:  certTestCurrentTime.Add(-48 * time.Hour),
	})
	unrelated := newCertVerifyMatchFixture(t, certFixtureOptions{})
	dir := t.TempDir()
	bundlePath := writeCertTestFile(t, dir, "bundle.pem", fixture.leafPEM, unrelated.leafPEM)
	keyPath := writeCertTestFile(t, dir, "key.pem", fixture.leafKeyPKCS8PEM)
	csrPath := writeCertTestFile(t, dir, "request.pem", fixture.leafCSRPEM)
	wrongKeyPath := writeCertTestFile(t, dir, "wrong-key.pem", unrelated.leafKeyPKCS8PEM)

	stdout, _, err := executeRootStreams(t, "cert", "match", "--cert", bundlePath, "--key", keyPath, "--csr", csrPath, "--format", "json")
	require.NoError(t, err, "expired, untrusted certificate and differently-subjected CSR should still key-match: %v", err)
	assertCertBooleanReport(t, stdout, "match", true)

	stdout, _, err = executeRootStreams(t, "cert", "match", "--cert", bundlePath, "--key", wrongKeyPath, "--format", "json")
	if err == nil {
		t.Fatal("mismatched keys returned success")
	}
	assertCertBooleanReport(t, stdout, "match", false)
	assertCertReportPublicDetails(t, stdout)
	mismatchOutput := fixturePath(t, dir, "mismatch.out", []byte("preserve"))
	_, _, err = executeRootStreams(t, "cert", "match", "--cert", bundlePath, "--key", wrongKeyPath, "--output", mismatchOutput)
	if err == nil {
		t.Fatal("mismatched keys returned success")
	}
	if data, readErr := os.ReadFile(mismatchOutput); readErr != nil || string(data) == "preserve" {
		t.Fatalf("completed mismatch did not replace output: data=%q err=%v", data, readErr)
	}

	badCSR := bytes.Clone(fixture.leafCSRDER)
	badCSR[len(badCSR)-1] ^= 1
	badCSRPath := writeCertTestFile(t, dir, "bad.csr", badCSR)
	stdout, _, err = executeRootStreams(t, "cert", "match", "--key", keyPath, "--csr", badCSRPath, "--format", "json")
	if err == nil {
		t.Fatal("CSR with invalid signature returned success")
	}
	require.Empty(t, stdout, "invalid CSR signature produced completed match report %q", stdout)

	malformedBundlePath := writeCertTestFile(t, dir, "malformed-bundle.pem", fixture.leafPEM, []byte("trailing data"))
	outputPath := fixturePath(t, dir, "preserved.out", []byte("preserve"))
	_, _, err = executeRootStreams(t, "cert", "match", "--cert", malformedBundlePath, "--key", keyPath, "--output", outputPath)
	if err == nil {
		t.Fatal("trailing certificate bundle data returned success")
	}
	if data, readErr := os.ReadFile(outputPath); readErr != nil || string(data) != "preserve" {
		t.Fatalf("malformed bundle changed output: data=%q err=%v", data, readErr)
	}
	for name, operand := range map[string]string{"key": "not a key", "csr": "not a CSR"} {
		malformedPath := fixturePath(t, dir, "malformed-"+name, []byte(operand))
		preservedPath := fixturePath(t, dir, "preserved-"+name, []byte("preserve"))
		args := []string{"cert", "match", "--cert", bundlePath, "--" + name, malformedPath, "--output", preservedPath}
		_, _, runErr := executeRootStreams(t, args...)
		if runErr == nil {
			t.Errorf("malformed %s returned success", name)
		}
		if data, readErr := os.ReadFile(preservedPath); readErr != nil || string(data) != "preserve" {
			t.Errorf("malformed %s changed output: data=%q err=%v", name, data, readErr)
		}
	}
}

func TestCertMatchAcceptsPEMHeaderContainingBeginMarker(t *testing.T) {
	t.Parallel()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{})
	requestPEM := pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE REQUEST",
		Headers: map[string]string{"Comment": "ordinary -----BEGIN marker"},
		Bytes:   fixture.leafCSRDER,
	})
	if len(requestPEM) == 0 || !bytes.Contains(requestPEM, []byte("Comment: ordinary -----BEGIN marker")) {
		t.Fatal("stdlib did not encode the CSR PEM header fixture")
	}
	request, err := x509.ParseCertificateRequest(fixture.leafCSRDER)
	require.NoError(t, err, "stdlib rejected CSR DER fixture: %v", err)
	if err := request.CheckSignature(); err != nil {
		t.Fatalf("stdlib rejected CSR signature fixture: %v", err)
	}

	dir := t.TempDir()
	keyPath := writeCertTestFile(t, dir, "key.pem", fixture.leafKeyPKCS8PEM)
	csrPath := writeCertTestFile(t, dir, "request.pem", requestPEM)
	stdout, stderr, err := executeRootStreams(t,
		"cert", "match", "--key", keyPath, "--csr", csrPath, "--format", "json",
	)
	require.NoError(t, err, "valid CSR PEM header rejected: %v (stderr %q)", err, stderr)
	assertCertBooleanReport(t, stdout, "match", true)
}

func TestCertMatchStdinSelection(t *testing.T) {
	t.Parallel()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{})
	dir := t.TempDir()
	certPath := writeCertTestFile(t, dir, "cert.pem", fixture.leafPEM)
	keyPath := writeCertTestFile(t, dir, "key.pem", fixture.leafKeyPKCS8PEM)

	stdout, _, err := executeCertTestWithInput(t, fixture.leafKeyPKCS8PEM, "cert", "match", "--cert", certPath, "--key", "-", "--format", "json")
	require.NoError(t, err, "one stdin operand: %v", err)
	assertCertBooleanReport(t, stdout, "match", true)

	stdout, _, err = executeCertTestWithInput(t, []byte("ignored stdin"),
		"cert", "match", "--cert", certPath, "--key", "-", "--input", keyPath, "--format", "json",
	)
	require.NoError(t, err, "redirected stdin operand: %v", err)
	assertCertBooleanReport(t, stdout, "match", true)

	encodedKey := []byte(base64.StdEncoding.EncodeToString(fixture.leafKeyPKCS8PEM))
	for _, test := range []struct {
		name  string
		input []byte
		args  []string
	}{
		{name: "encoded stdin", input: encodedKey},
		{
			name: "encoded redirected input", input: []byte("ignored invalid stdin"),
			args: []string{"--input", writeCertTestFile(t, dir, "key.b64", encodedKey)},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := []string{"cert", "match", "--cert", certPath, "--key", "-", "--input-encoding", "base64", "--format", "json"}
			reportOutput, _, matchErr := executeCertTestWithInput(t, test.input, append(args, test.args...)...)
			require.NoError(t, matchErr)
			assertCertBooleanReport(t, reportOutput, "match", true)
		})
	}

	t.Run("encoding requires a stdin operand before IO", func(t *testing.T) {
		t.Parallel()
		outputPath := fixturePath(t, t.TempDir(), "output", []byte("preserve"))
		root := newRootCmd()
		input := &certVerifyReadCounter{}
		root.SetIn(input)
		_, _, err := executeRootCommandStreams(t, root,
			"cert", "match", "--cert", certPath, "--key", keyPath, "--input-encoding", "base64", "--output", outputPath,
		)
		require.ErrorIs(t, err, errCertificateInputSelection)
		require.Zero(t, input.count.Load())
		contents, readErr := os.ReadFile(outputPath)
		require.NoError(t, readErr)
		require.Equal(t, []byte("preserve"), contents)
	})

	if _, _, err = executeCertTestWithInput(t, fixture.leafPEM, "cert", "match", "--cert", "-", "--key", "-"); err == nil {
		t.Fatal("multiple stdin operands returned success")
	}
	if _, _, err = executeRootStreams(t, "cert", "match", "--cert", certPath, "--key", keyPath, "--input", keyPath); err == nil {
		t.Fatal("unused explicit --input returned success")
	}
	if _, _, err = executeRootStreams(t, "cert", "match", "--cert", certPath); err == nil {
		t.Fatal("one operand returned success")
	}
}

func TestCertVerifyAndMatchArtifactLimits(t *testing.T) {
	t.Parallel()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{})
	dir := t.TempDir()
	rootPath := writeCertTestFile(t, dir, "root.pem", fixture.rootPEM)
	keyPath := writeCertTestFile(t, dir, "key.pem", fixture.leafKeyPKCS8PEM)

	certificateAtLimit := writeCertTestFile(t, dir, "cert-at-limit", bytes.Repeat([]byte{'x'}, int(artifact.MaxCertificateBytes)))
	certificateOverLimit := writeCertTestFile(t, dir, "cert-over-limit", bytes.Repeat([]byte{'x'}, int(artifact.MaxCertificateBytes+1)))
	atLimitData, err := os.ReadFile(certificateAtLimit)
	require.NoError(t, err)
	_, _, err = executeRootStreamsWithInput(t, strings.NewReader(base64.StdEncoding.EncodeToString(atLimitData)),
		"cert", "verify", "--input-encoding", "base64", "--ca", rootPath,
	)
	if err == nil || errors.Is(err, artifact.ErrTooLarge) {
		t.Fatalf("certificate at limit error = %v, want parse error without size rejection", err)
	}
	overLimitData, err := os.ReadFile(certificateOverLimit)
	require.NoError(t, err)
	outputPath := fixturePath(t, dir, "output", []byte("preserve"))
	_, _, err = executeRootStreamsWithInput(t, strings.NewReader(base64.StdEncoding.EncodeToString(overLimitData)),
		"cert", "verify", "--input-encoding", "base64", "--ca", rootPath, "--output", outputPath,
	)
	require.ErrorIs(t, err, artifact.ErrTooLarge, "certificate over limit error = %v, want artifact.ErrTooLarge", err)
	contents, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	require.Equal(t, []byte("preserve"), contents)
	_, _, err = executeRootStreams(t, "cert", "match", "--cert", certificateAtLimit, "--key", keyPath)
	if err == nil || errors.Is(err, artifact.ErrTooLarge) {
		t.Fatalf("match certificate at limit error = %v, want parse error without size rejection", err)
	}
	_, _, err = executeRootStreams(t, "cert", "match", "--cert", certificateOverLimit, "--key", keyPath)
	require.ErrorIs(t, err, artifact.ErrTooLarge, "match certificate over limit error = %v, want artifact.ErrTooLarge", err)

	keyAtLimit := writeCertTestFile(t, dir, "key-at-limit", bytes.Repeat([]byte{'x'}, int(artifact.MaxKeyBytes)))
	keyOverLimit := writeCertTestFile(t, dir, "key-over-limit", bytes.Repeat([]byte{'x'}, int(artifact.MaxKeyBytes+1)))
	_, _, err = executeRootStreams(t, "cert", "match", "--key", keyAtLimit, "--csr", fixturePath(t, dir, "valid.csr", fixture.leafCSRPEM))
	if err == nil || errors.Is(err, artifact.ErrTooLarge) {
		t.Fatalf("key at limit error = %v, want parse error without size rejection", err)
	}
	_, _, err = executeRootStreams(t, "cert", "match", "--key", keyOverLimit, "--csr", fixturePath(t, dir, "valid-again.csr", fixture.leafCSRPEM))
	require.ErrorIs(t, err, artifact.ErrTooLarge, "key over limit error = %v, want artifact.ErrTooLarge", err)

	csrAtLimit := writeCertTestFile(t, dir, "csr-at-limit", bytes.Repeat([]byte{'x'}, int(artifact.MaxKeyBytes)))
	csrOverLimit := writeCertTestFile(t, dir, "csr-over-limit", bytes.Repeat([]byte{'x'}, int(artifact.MaxKeyBytes+1)))
	_, _, err = executeRootStreams(t, "cert", "match", "--key", keyPath, "--csr", csrAtLimit)
	if err == nil || errors.Is(err, artifact.ErrTooLarge) {
		t.Fatalf("CSR at limit error = %v, want parse error without size rejection", err)
	}
	_, _, err = executeRootStreams(t, "cert", "match", "--key", keyPath, "--csr", csrOverLimit)
	require.ErrorIs(t, err, artifact.ErrTooLarge, "CSR over limit error = %v, want artifact.ErrTooLarge", err)
}

func TestCertCommandsUseProcessExitStatus(t *testing.T) {
	t.Parallel()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{})
	dir := t.TempDir()
	chainPath := writeCertTestFile(t, dir, "chain.pem", fixture.leafPEM, fixture.intermediatePEM)
	rootPath := writeCertTestFile(t, dir, "root.pem", fixture.rootPEM)
	wrongRootPath := writeCertTestFile(t, dir, "wrong-root.pem", newCertVerifyMatchFixture(t, certFixtureOptions{}).rootPEM)

	positive := runCertTestProcess(t, "cert", "verify", "--input", chainPath, "--ca", rootPath, "--at", certTestCurrentTime.Format(certTestRFC3339))
	require.Equal(t, 0, positive, "verified process exit status = %d, want 0", positive)
	negative := runCertTestProcess(t, "cert", "verify", "--input", chainPath, "--ca", wrongRootPath, "--at", certTestCurrentTime.Format(certTestRFC3339))
	if negative == 0 {
		t.Fatal("negative verification process exit status = 0, want nonzero")
	}
}

func TestCertCommandHelperProcess(t *testing.T) {
	t.Parallel()
	if os.Getenv("NPC_CERT_TEST_HELPER") != "1" {
		return
	}
	separator := slices.Index(os.Args, "--")
	if separator < 0 {
		os.Exit(2)
	}
	root := newRootCmd()
	root.SetArgs(os.Args[separator+1:])
	root.SetIn(os.Stdin)
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
	if err := commandio.Execute(root); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func runCertTestProcess(t *testing.T, args ...string) int {
	t.Helper()
	processArgs := append([]string{"-test.run=^TestCertCommandHelperProcess$", "--"}, args...)
	command := exec.CommandContext(t.Context(), os.Args[0], processArgs...)
	command.Env = append(os.Environ(), "NPC_CERT_TEST_HELPER=1")
	err := command.Run()
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("run helper process: %v", err)
	}
	return exitError.ExitCode()
}

func newCertVerifyMatchFixture(tb testing.TB, options certFixtureOptions) *certVerifyMatchFixture { //nolint:gocritic // value options keep call sites clear
	tb.Helper()
	rootPublic, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cert test root"},
		NotBefore:             certTestCurrentTime.Add(-10 * 365 * 24 * time.Hour),
		NotAfter:              certTestCurrentTime.Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:            2,
	}
	if options.rootMaxPathLenZero {
		rootTemplate.MaxPathLen = 0
		rootTemplate.MaxPathLenZero = true
	}
	rootDER := certTestCreateCertificate(tb, rootTemplate, rootTemplate, rootPublic, rootKey)
	root := certTestParseCertificate(tb, rootDER)

	intermediatePublic, intermediateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	intermediateIsCA := true
	if options.intermediateKeyUsage != 0 || options.intermediateIsCA {
		intermediateIsCA = options.intermediateIsCA
	}
	intermediateKeyUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if options.intermediateKeyUsage != 0 {
		intermediateKeyUsage = options.intermediateKeyUsage
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "cert test intermediate"},
		NotBefore:             root.NotBefore.Add(time.Hour),
		NotAfter:              root.NotAfter.Add(-time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  intermediateIsCA,
		KeyUsage:              intermediateKeyUsage,
	}
	if intermediateIsCA {
		intermediateTemplate.MaxPathLen = 0
		intermediateTemplate.MaxPathLenZero = true
	}
	intermediateDER := certTestCreateCertificate(tb, intermediateTemplate, root, intermediatePublic, rootKey)
	intermediate := certTestParseCertificate(tb, intermediateDER)

	leafKey := options.leafKey
	if leafKey == nil {
		_, generated, generateErr := ed25519.GenerateKey(rand.Reader)
		if generateErr != nil {
			tb.Fatal(generateErr)
		}
		leafKey = generated
	}
	notBefore := certTestCurrentTime.Add(-24 * time.Hour)
	if !options.leafNotBefore.IsZero() {
		notBefore = options.leafNotBefore
	}
	notAfter := certTestCurrentTime.Add(24 * time.Hour)
	if !options.leafNotAfter.IsZero() {
		notAfter = options.leafNotAfter
	}
	extKeyUsage := options.extKeyUsage
	if extKeyUsage == nil {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	dnsNames := options.dnsNames
	if dnsNames == nil {
		dnsNames = []string{certTestDNSName}
	}
	ipAddresses := options.ipAddresses
	if ipAddresses == nil {
		ipAddresses = []net.IP{net.ParseIP("192.0.2.10")}
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "subject differs from CSR"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           extKeyUsage,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		ExtraExtensions:       options.extraExtensions,
		IssuingCertificateURL: options.issuingCertificateURL,
		OCSPServer:            options.ocspServer,
		CRLDistributionPoints: options.crlDistributionPoints,
	}
	leafDER := certTestCreateCertificate(tb, leafTemplate, intermediate, leafKey.Public(), intermediateKey)
	leaf := certTestParseCertificate(tb, leafDER)
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		tb.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "deliberately different CSR subject"},
	}, leafKey)
	if err != nil {
		tb.Fatal(err)
	}
	return &certVerifyMatchFixture{
		root:            root,
		intermediate:    intermediate,
		leaf:            leaf,
		rootPEM:         pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: rootDER}),
		intermediatePEM: pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: intermediateDER}),
		leafPEM:         pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: leafDER}),
		leafDER:         leafDER,
		leafKey:         leafKey,
		leafKeyPKCS8PEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		leafCSRDER:      csrDER,
		leafCSRPEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
	}
}

func certTestCreateCertificate(tb testing.TB, template, parent *x509.Certificate, publicKey any, signer crypto.Signer) []byte {
	tb.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	if err != nil {
		tb.Fatal(err)
	}
	return der
}

func assertCertReportDetailsIdentifyLink(t *testing.T, output string, first, second int) {
	t.Helper()
	details := strings.ToLower(certTestReportDetails(t, output))
	for _, index := range []int{first, second} {
		want := fmt.Sprintf("certificate %d", index)
		if !strings.Contains(details, want) {
			t.Fatalf("details = %q, want identification of %s", details, want)
		}
	}
}

func assertCertReportValidPiecesWrongOrder(t *testing.T, output string) {
	t.Helper()
	details := strings.ToLower(certTestReportDetails(t, output))
	if !strings.Contains(details, "valid") || !strings.Contains(details, "order") {
		t.Fatalf("details = %q, want valid pieces and wrong order diagnosis", details)
	}
}

func certTestReportDetails(t *testing.T, output string) string {
	t.Helper()
	var report struct {
		Details string `json:"details"`
	}
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("decode certificate report details: %v", err)
	}
	return report.Details
}

func certTestClaimsAllPiecesValid(details string) bool {
	return strings.Contains(details, "valid chain") ||
		strings.Contains(details, "valid certificates") ||
		strings.Contains(details, "certificates are valid") ||
		strings.Contains(details, "valid pieces")
}

func certTestVerifyOrderedFixture(fixture *certVerifyMatchFixture, at time.Time) error {
	roots := x509.NewCertPool()
	roots.AddCert(fixture.root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(fixture.intermediate)
	_, err := fixture.leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		CurrentTime: at,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("verify ordered fixture: %w", err)
	}
	return nil
}

func certTestSameNameCAFirstChain(tb testing.TB, trustedRoot *x509.Certificate) []byte {
	tb.Helper()
	rootPublic, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(41),
		Subject:               trustedRoot.Subject,
		NotBefore:             trustedRoot.NotBefore,
		NotAfter:              trustedRoot.NotAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER := certTestCreateCertificate(tb, rootTemplate, rootTemplate, rootPublic, rootKey)
	root := certTestParseCertificate(tb, rootDER)
	leafPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               trustedRoot.Subject,
		NotBefore:             certTestCurrentTime.Add(-time.Hour),
		NotAfter:              certTestCurrentTime.Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER := certTestCreateCertificate(tb, leafTemplate, root, leafPublic, rootKey)
	leaf := certTestParseCertificate(tb, leafDER)
	if !bytes.Equal(trustedRoot.RawIssuer, root.RawSubject) || !bytes.Equal(root.RawIssuer, leaf.RawSubject) {
		tb.Fatal("same-name fixture does not have name-adjacent certificates")
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: trustedRoot.Raw})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: rootDER})...)
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: leafDER})...)
	return chain
}

func certTestParseCertificate(tb testing.TB, der []byte) *x509.Certificate {
	tb.Helper()
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	return certificate
}

func certTestGeneralKeyContainers(tb testing.TB, signer crypto.Signer) [][]byte {
	tb.Helper()
	privateDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		tb.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		tb.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		tb.Fatal(err)
	}
	sshPrivate, err := ssh.MarshalPrivateKey(signer, "cert match fixture")
	if err != nil {
		tb.Fatal(err)
	}
	return [][]byte{
		privateDER,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
		publicDER,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}),
		ssh.MarshalAuthorizedKey(sshPublic),
		pem.EncodeToMemory(sshPrivate),
	}
}

func certTestECDSAKeyContainers(tb testing.TB, signer crypto.Signer) [][]byte {
	tb.Helper()
	containers := certTestGeneralKeyContainers(tb, signer)
	privateKey, ok := signer.(*ecdsa.PrivateKey)
	if !ok {
		tb.Fatalf("signer = %T, want ECDSA", signer)
	}
	der, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		tb.Fatal(err)
	}
	return append(containers, der, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func certTestRSAKeyContainers(tb testing.TB, signer crypto.Signer) [][]byte {
	tb.Helper()
	containers := certTestGeneralKeyContainers(tb, signer)
	privateKey, ok := signer.(*rsa.PrivateKey)
	if !ok {
		tb.Fatalf("signer = %T, want RSA", signer)
	}
	der := x509.MarshalPKCS1PrivateKey(privateKey)
	return append(containers,
		der,
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}),
	)
}

func fixturePath(tb testing.TB, dir, name string, data []byte) string {
	tb.Helper()
	return writeCertTestFileTB(tb, dir, name, data)
}

func writeCertTestFileTB(tb testing.TB, dir, name string, data []byte) string {
	tb.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		tb.Fatal(err)
	}
	return path
}

func executeCertTestWithInput(t *testing.T, input []byte, args ...string) (string, string, error) {
	t.Helper()
	root := newRootCmd()
	root.SetIn(bytes.NewReader(input))
	return executeRootCommandStreams(t, root, args...)
}
