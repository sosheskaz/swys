package cert_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/artifact"
)

const certFuzzMaxMutableArtifact = 64 << 10

var errCertFuzzOracle = errors.New("certificate fuzz oracle rejected input")

func FuzzCertVerifyStrictFraming(f *testing.F) {
	fixture := newCertVerifyMatchFixture(f, certFixtureOptions{})
	dir := f.TempDir()
	rootPath := writeCertTestFileTB(f, dir, "root.pem", fixture.rootPEM)
	intermediatePath := writeCertTestFileTB(f, dir, "intermediate.pem", fixture.intermediatePEM)
	chain := append(bytes.Clone(fixture.leafPEM), fixture.intermediatePEM...)
	f.Add(fixture.leafDER)
	f.Add(fixture.leafPEM)
	f.Add(chain)
	f.Add(fixture.leafDER[:len(fixture.leafDER)-1])
	f.Add(append([]byte{0}, fixture.leafDER...))
	f.Add(append(bytes.Clone(chain), 0))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > certFuzzMaxMutableArtifact {
			t.Skip()
		}
		wantVerified, classification := certFuzzVerifyOracle(t, data, fixture.root, fixture.intermediate)
		stdout, stderr, err := executeCertTestWithInput(t, data,
			"cert", "verify", "--ca", rootPath, "--intermediates", intermediatePath,
			"--at", certTestCurrentTime.Format(certTestRFC3339), "--format", "json",
		)
		switch classification {
		case certFuzzMalformed:
			if err == nil {
				t.Fatal("malformed PEM/DER certificate input returned success")
			}
			if stdout != "" {
				t.Fatalf("malformed certificate input produced report %q", stdout)
			}
		case certFuzzCompleted:
			if wantVerified && err != nil {
				t.Fatalf("stdlib-verified certificate rejected: %v (stderr %q)", err, stderr)
			}
			if !wantVerified && !errors.Is(err, errCertificateReportNegative) {
				t.Fatalf("negative verification error = %v, want completed negative report", err)
			}
			assertCertBooleanReport(t, stdout, "verified", wantVerified)
		default:
			t.Fatalf("unknown oracle classification %d", classification)
		}
	})
}

func FuzzCertVerifyBoundedChains(f *testing.F) {
	fixture := newCertVerifyMatchFixture(f, certFixtureOptions{})
	dir := f.TempDir()
	rootPath := writeCertTestFileTB(f, dir, "root.pem", fixture.rootPEM)
	f.Add(uint8(0))
	f.Add(uint8(1))
	f.Add(uint8(2))
	f.Add(uint8(8))
	f.Add(uint8(32))

	f.Fuzz(func(t *testing.T, rawCount uint8) {
		count := int(rawCount % 33)
		chain := append([]byte(nil), fixture.leafPEM...)
		for range count {
			chain = append(chain, fixture.intermediatePEM...)
		}
		stdout, _, err := executeCertTestWithInput(t, chain,
			"cert", "verify", "--ca", rootPath,
			"--at", certTestCurrentTime.Format(certTestRFC3339), "--format", "json",
		)
		switch count {
		case 0:
			if !errors.Is(err, errCertificateReportNegative) {
				t.Fatalf("leaf without intermediate error = %v, want completed negative report", err)
			}
			assertCertBooleanReport(t, stdout, "verified", false)
		case 1:
			if err != nil {
				t.Fatalf("ordered leaf-first chain: %v", err)
			}
			assertCertBooleanReport(t, stdout, "verified", true)
		default:
			if !errors.Is(err, errCertificateReportNegative) {
				t.Fatalf("duplicate out-of-order chain error = %v, want completed negative report", err)
			}
			assertCertBooleanReport(t, stdout, "verified", false)
			assertCertReportDetailsIdentifyLink(t, stdout, 2, 3)
		}
	})
}

func FuzzCertMatchCanonicalPublicKeys(f *testing.F) {
	matching := newCertVerifyMatchFixture(f, certFixtureOptions{})
	unrelated := newCertVerifyMatchFixture(f, certFixtureOptions{})
	dir := f.TempDir()
	certPath := writeCertTestFileTB(f, dir, "cert.pem", matching.leafPEM)
	for _, signer := range []crypto.Signer{matching.leafKey, unrelated.leafKey} {
		for _, keyData := range certTestGeneralKeyContainers(f, signer) {
			f.Add(keyData)
		}
	}
	for _, keyData := range certFuzzInconsistentOpenSSHEd25519Keys(f, matching.leafKey) {
		f.Add(keyData)
	}
	f.Add([]byte("not a key"))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----"))
	f.Add([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\na0==\n-----END OPENSSH PRIVATE KEY-----"))
	f.Add(matching.leafKeyPKCS8PEM[:len(matching.leafKeyPKCS8PEM)-1])
	wantCanonical := certTestPublicKeyDER(f, matching.leafKey.Public())

	f.Fuzz(func(t *testing.T, keyData []byte) {
		if len(keyData) > certFuzzMaxMutableArtifact {
			t.Skip()
		}
		gotCanonical, oracleErr := certFuzzCanonicalPublicKey(keyData)
		stdout, stderr, err := executeCertTestWithInput(t, keyData,
			"cert", "match", "--cert", certPath, "--key", "-", "--format", "json",
		)
		if oracleErr != nil {
			require.Error(t, err, "stdlib-invalid key returned success; oracle error: %v", oracleErr)
			require.Empty(t, stdout, "malformed key produced report %q", stdout)
			assertNoPrivateKeyMaterial(t, stderr+err.Error(), keyData)
			return
		}
		wantMatch := bytes.Equal(gotCanonical, wantCanonical)
		if wantMatch && err != nil {
			t.Fatalf("canonical matching public key rejected: %v (stderr %q)", err, stderr)
		}
		if !wantMatch && !errors.Is(err, errCertificateReportNegative) {
			t.Fatalf("canonical mismatch error = %v, want completed negative report", err)
		}
		assertCertBooleanReport(t, stdout, "match", wantMatch)
		assertNoPrivateKeyMaterial(t, stdout+stderr, keyData)
	})
}

func FuzzCertMatchCSRSignature(f *testing.F) {
	matching := newCertVerifyMatchFixture(f, certFixtureOptions{})
	unrelated := newCertVerifyMatchFixture(f, certFixtureOptions{})
	dir := f.TempDir()
	keyPath := writeCertTestFileTB(f, dir, "key.pem", matching.leafKeyPKCS8PEM)
	badSignature := bytes.Clone(matching.leafCSRDER)
	badSignature[len(badSignature)-1] ^= 1
	headerMarkerPEM := pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE REQUEST",
		Headers: map[string]string{"Comment": "ordinary -----BEGIN marker"},
		Bytes:   matching.leafCSRDER,
	})
	for _, csrData := range [][]byte{
		matching.leafCSRDER,
		matching.leafCSRPEM,
		headerMarkerPEM,
		unrelated.leafCSRDER,
		unrelated.leafCSRPEM,
		badSignature,
		matching.leafCSRDER[:len(matching.leafCSRDER)-1],
		append([]byte("-----BEGIN CERTIFICATE REQUEST-----\n!\n-----END CERTIFICATE REQUEST-----\n"), matching.leafCSRPEM...),
		append(bytes.Clone(headerMarkerPEM), []byte("trailing")...),
		[]byte("not a CSR"),
	} {
		f.Add(csrData)
	}
	wantCanonical := certTestPublicKeyDER(f, matching.leafKey.Public())

	f.Fuzz(func(t *testing.T, csrData []byte) {
		if len(csrData) > certFuzzMaxMutableArtifact {
			t.Skip()
		}
		request, oracleErr := certFuzzParseCSR(csrData)
		if oracleErr == nil {
			oracleErr = request.CheckSignature()
		}
		stdout, stderr, err := executeCertTestWithInput(t, csrData,
			"cert", "match", "--key", keyPath, "--csr", "-", "--format", "json",
		)
		if oracleErr != nil {
			require.Error(t, err, "malformed or signature-invalid CSR returned success; oracle error: %v", oracleErr)
			require.Empty(t, stdout, "invalid CSR produced report %q", stdout)
			return
		}
		gotCanonical, marshalErr := x509.MarshalPKIXPublicKey(request.PublicKey)
		require.NoError(t, marshalErr)
		wantMatch := bytes.Equal(gotCanonical, wantCanonical)
		if wantMatch && err != nil {
			t.Fatalf("valid matching CSR rejected: %v (stderr %q)", err, stderr)
		}
		if !wantMatch && !errors.Is(err, errCertificateReportNegative) {
			t.Fatalf("valid CSR mismatch error = %v, want completed negative report", err)
		}
		assertCertBooleanReport(t, stdout, "match", wantMatch)
	})
}

func FuzzCertArtifactLimits(f *testing.F) {
	const gate = uint32(0x43525431)
	fixture := newCertVerifyMatchFixture(f, certFixtureOptions{})
	dir := f.TempDir()
	rootPath := writeCertTestFileTB(f, dir, "root.pem", fixture.rootPEM)
	keyPath := writeCertTestFileTB(f, dir, "key.pem", fixture.leafKeyPKCS8PEM)
	csrPath := writeCertTestFileTB(f, dir, "request.pem", fixture.leafCSRPEM)
	for rawKind := range 3 {
		kind := uint8(rawKind)
		for _, delta := range []int8{-1, 0, 1} {
			f.Add(kind, delta, gate)
		}
	}

	f.Fuzz(func(t *testing.T, kind uint8, delta int8, fuzzGate uint32) {
		if fuzzGate != gate || delta < -1 || delta > 1 || kind > 2 {
			return
		}
		limit := artifact.MaxKeyBytes
		args := []string{"cert", "match", "--key", "-", "--csr", csrPath}
		switch kind {
		case 0:
			limit = artifact.MaxCertificateBytes
			args = []string{"cert", "verify", "--ca", rootPath}
		case 1:
			// The default args exercise the key limit.
		case 2:
			args = []string{"cert", "match", "--key", keyPath, "--csr", "-"}
		}
		input := io.LimitReader(certFuzzFillReader{}, limit+int64(delta))
		stdout, _, err := executeCertTestWithReader(t, input, args...)
		if delta == 1 {
			require.ErrorIs(t, err, artifact.ErrTooLarge, "kind %d over-limit error = %v, want artifact.ErrTooLarge", kind, err)
		} else if err == nil || errors.Is(err, artifact.ErrTooLarge) {
			t.Fatalf("kind %d delta %d error = %v, want parse error within limit", kind, delta, err)
		}
		assert.Empty(t, stdout, "invalid boundary artifact produced report %q", stdout)
	})
}

func FuzzCertMatchDiagnosticsDoNotLeakPrivateBytes(f *testing.F) {
	fixture := newCertVerifyMatchFixture(f, certFixtureOptions{})
	dir := f.TempDir()
	certPath := writeCertTestFileTB(f, dir, "cert.pem", fixture.leafPEM)
	f.Add([]byte{})
	f.Add([]byte("\n"))
	f.Add([]byte("trailing"))
	f.Add(bytes.Repeat([]byte{'x'}, 1024))

	f.Fuzz(func(t *testing.T, suffix []byte) {
		if len(suffix) > 4096 {
			t.Skip()
		}
		input := append(bytes.Clone(fixture.leafKeyPKCS8PEM), suffix...)
		stdout, stderr, err := executeCertTestWithInput(t, input,
			"cert", "match", "--cert", certPath, "--key", "-", "--format", "json",
		)
		diagnostics := stdout + stderr
		if err != nil {
			diagnostics += err.Error()
		}
		assertNoPrivateKeyMaterial(t, diagnostics, fixture.leafKeyPKCS8PEM)
	})
}

type certFuzzClassification uint8

const (
	certFuzzMalformed certFuzzClassification = iota
	certFuzzCompleted
)

func certFuzzVerifyOracle(
	tb testing.TB,
	data []byte,
	root, additionalIntermediate *x509.Certificate,
) (bool, certFuzzClassification) {
	tb.Helper()
	certificates, err := certFuzzParseCertificates(data)
	if err != nil {
		return false, certFuzzMalformed
	}
	adjacentValid := true
	for index := range len(certificates) - 1 {
		if !bytes.Equal(certificates[index].RawIssuer, certificates[index+1].RawSubject) {
			adjacentValid = false
		}
		if err := certificates[index].CheckSignatureFrom(certificates[index+1]); err != nil {
			adjacentValid = false
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(additionalIntermediate)
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	_, verifyErr := certificates[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		CurrentTime: certTestCurrentTime,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return adjacentValid && verifyErr == nil, certFuzzCompleted
}

func certFuzzParseCertificates(data []byte) ([]*x509.Certificate, error) {
	trimmed := bytes.TrimSpace(data)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		certificate, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, fmt.Errorf("%w: parse DER certificate: %w", errCertFuzzOracle, err)
		}
		return []*x509.Certificate{certificate}, nil
	}
	var certificates []*x509.Certificate
	for len(trimmed) > 0 {
		block, rest, err := certFuzzDecodeFirstPEM(trimmed)
		if err != nil {
			return nil, err
		}
		if block.Type != certificatePEMType {
			return nil, fmt.Errorf("%w: certificate PEM type %q", errCertFuzzOracle, block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parse PEM certificate: %w", errCertFuzzOracle, err)
		}
		certificates = append(certificates, certificate)
		trimmed = bytes.TrimSpace(rest)
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("%w: no certificates", errCertFuzzOracle)
	}
	return certificates, nil
}

func certFuzzParseCSR(data []byte) (*x509.CertificateRequest, error) {
	trimmed := bytes.TrimSpace(data)
	der := data
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		block, rest, err := certFuzzDecodeFirstPEM(certFuzzMaskPEMHeaderBeginMarkers(trimmed))
		if err != nil {
			return nil, err
		}
		if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
			return nil, fmt.Errorf("%w: CSR PEM type %q", errCertFuzzOracle, block.Type)
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("%w: trailing CSR data", errCertFuzzOracle)
		}
		der = block.Bytes
	}
	request, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("%w: parse CSR: %w", errCertFuzzOracle, err)
	}
	return request, nil
}

func certFuzzMaskPEMHeaderBeginMarkers(data []byte) []byte {
	masked := bytes.Clone(data)
	lineStart := bytes.IndexByte(masked, '\n') + 1
	if lineStart == 0 {
		return masked
	}
	for lineStart < len(masked) {
		lineLength := bytes.IndexByte(masked[lineStart:], '\n')
		if lineLength < 0 {
			lineLength = len(masked) - lineStart
		}
		line := masked[lineStart : lineStart+lineLength]
		if len(bytes.TrimSpace(line)) == 0 {
			break
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			break
		}
		value := line[colon+1:]
		for marker := bytes.Index(value, []byte("-----BEGIN ")); marker >= 0; marker = bytes.Index(value, []byte("-----BEGIN ")) {
			copy(value[marker:marker+len("-----BEGIN ")], "_____BEGIN ")
			value = value[marker+len("-----BEGIN "):]
		}
		lineStart += lineLength + 1
	}
	return masked
}

func certFuzzCanonicalPublicKey(data []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return certFuzzCanonicalPEMKey(trimmed)
	}
	material, err := certFuzzParseDEROrSSHKey(data, trimmed)
	if err != nil {
		return nil, err
	}
	return certFuzzMarshalPublicKey(material)
}

func certFuzzCanonicalPEMKey(trimmed []byte) ([]byte, error) {
	block, rest, err := certFuzzDecodeFirstPEM(trimmed)
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: invalid key PEM framing", errCertFuzzOracle)
	}
	var material any
	switch block.Type {
	case "PRIVATE KEY":
		material, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		material, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		material, err = x509.ParseECPrivateKey(block.Bytes)
	case "PUBLIC KEY":
		material, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "OPENSSH PRIVATE KEY":
		material, err = certFuzzParseOpenSSHPrivateKey(trimmed, block.Bytes)
	default:
		return nil, fmt.Errorf("%w: unexpected key PEM type %q", errCertFuzzOracle, block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: parse key PEM: %w", errCertFuzzOracle, err)
	}
	return certFuzzMarshalPublicKey(material)
}

type certFuzzOpenSSHPrivateEnvelope struct { //nolint:govet // Field order is the OpenSSH wire format.
	CipherName   string
	KDFName      string
	KDFOptions   string
	NumKeys      uint32
	PublicKey    []byte
	PrivateBlock []byte
	Rest         []byte `ssh:"rest"`
}

type certFuzzOpenSSHPrivateHeader struct { //nolint:govet // Field order is the OpenSSH wire format.
	Check1, Check2 uint32
	Type           string
	Rest           []byte `ssh:"rest"`
}

type certFuzzOpenSSHEd25519Fields struct {
	Public, Private []byte
	Comment         string
	Padding         []byte `ssh:"rest"`
}

func certFuzzInconsistentOpenSSHEd25519Keys(tb testing.TB, signer crypto.Signer) [][]byte {
	tb.Helper()
	block, err := ssh.MarshalPrivateKey(signer, "cert match fuzz fixture")
	if err != nil {
		tb.Fatal(err)
	}
	mutate := func(change func(*certFuzzOpenSSHEd25519Fields)) []byte {
		var envelope certFuzzOpenSSHPrivateEnvelope
		if err := ssh.Unmarshal(block.Bytes[len("openssh-key-v1\x00"):], &envelope); err != nil {
			tb.Fatal(err)
		}
		var header certFuzzOpenSSHPrivateHeader
		if err := ssh.Unmarshal(envelope.PrivateBlock, &header); err != nil {
			tb.Fatal(err)
		}
		var fields certFuzzOpenSSHEd25519Fields
		if err := ssh.Unmarshal(header.Rest, &fields); err != nil {
			tb.Fatal(err)
		}
		change(&fields)
		header.Rest = ssh.Marshal(fields)
		envelope.PrivateBlock = ssh.Marshal(header)
		payload := append([]byte("openssh-key-v1\x00"), ssh.Marshal(envelope)...)
		return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: payload})
	}
	return [][]byte{
		mutate(func(fields *certFuzzOpenSSHEd25519Fields) {
			fields.Private = bytes.Clone(fields.Private)
			fields.Private[0] ^= 1
		}),
		mutate(func(fields *certFuzzOpenSSHEd25519Fields) {
			fields.Public = bytes.Clone(fields.Public)
			fields.Public[0] ^= 1
		}),
	}
}

func certFuzzParseOpenSSHPrivateKey(encoded, payload []byte) (any, error) {
	const authMagic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(payload, []byte(authMagic)) {
		return nil, fmt.Errorf("%w: invalid OpenSSH private-key magic", errCertFuzzOracle)
	}
	var envelope certFuzzOpenSSHPrivateEnvelope
	if err := ssh.Unmarshal(payload[len(authMagic):], &envelope); err != nil {
		return nil, fmt.Errorf("%w: parse OpenSSH private-key envelope: %w", errCertFuzzOracle, err)
	}
	if len(envelope.Rest) != 0 || envelope.NumKeys != 1 {
		return nil, fmt.Errorf("%w: invalid OpenSSH private-key envelope framing", errCertFuzzOracle)
	}
	if len(envelope.PrivateBlock) < 8 || len(envelope.PrivateBlock)%8 != 0 {
		return nil, fmt.Errorf("%w: invalid OpenSSH private-key block alignment", errCertFuzzOracle)
	}
	material, err := ssh.ParseRawPrivateKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: parse OpenSSH private key: %w", errCertFuzzOracle, err)
	}
	signer, ok := material.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: OpenSSH private key has no public key", errCertFuzzOracle)
	}
	outerPublic, err := ssh.ParsePublicKey(envelope.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: parse OpenSSH envelope public key: %w", errCertFuzzOracle, err)
	}
	derivedPublic, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("%w: derive OpenSSH public key: %w", errCertFuzzOracle, err)
	}
	if !bytes.Equal(outerPublic.Marshal(), derivedPublic.Marshal()) {
		return nil, fmt.Errorf("%w: OpenSSH public and private identities differ", errCertFuzzOracle)
	}
	if err := certFuzzValidateOpenSSHEd25519Fields(envelope.PrivateBlock, material); err != nil {
		return nil, err
	}
	return material, nil
}

func certFuzzValidateOpenSSHEd25519Fields(privateBlock []byte, material any) error {
	var private ed25519.PrivateKey
	switch key := material.(type) {
	case *ed25519.PrivateKey:
		if key == nil {
			return fmt.Errorf("%w: nil OpenSSH Ed25519 private key", errCertFuzzOracle)
		}
		private = *key
	case ed25519.PrivateKey:
		private = key
	default:
		return nil
	}
	var header certFuzzOpenSSHPrivateHeader
	if err := ssh.Unmarshal(privateBlock, &header); err != nil {
		return fmt.Errorf("%w: parse OpenSSH private header: %w", errCertFuzzOracle, err)
	}
	if header.Type != ssh.KeyAlgoED25519 {
		return fmt.Errorf("%w: OpenSSH private key type differs from Ed25519 material", errCertFuzzOracle)
	}
	var fields certFuzzOpenSSHEd25519Fields
	if err := ssh.Unmarshal(header.Rest, &fields); err != nil {
		return fmt.Errorf("%w: parse OpenSSH Ed25519 fields: %w", errCertFuzzOracle, err)
	}
	if len(fields.Private) != ed25519.PrivateKeySize || len(fields.Public) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid OpenSSH Ed25519 field lengths", errCertFuzzOracle)
	}
	derived := ed25519.NewKeyFromSeed(fields.Private[:ed25519.SeedSize])
	privateMatchesSeed := bytes.Equal(fields.Private, derived)
	publicMatchesSeed := bytes.Equal(fields.Public, derived[ed25519.SeedSize:])
	parsedMatchesSeed := bytes.Equal(private, derived)
	if !privateMatchesSeed || !publicMatchesSeed || !parsedMatchesSeed {
		return fmt.Errorf("%w: inconsistent OpenSSH Ed25519 key fields", errCertFuzzOracle)
	}
	return nil
}

func certFuzzParseDEROrSSHKey(data, trimmed []byte) (any, error) {
	parsers := []func([]byte) (any, error){
		x509.ParsePKCS8PrivateKey,
		func(der []byte) (any, error) { return x509.ParsePKCS1PrivateKey(der) },
		func(der []byte) (any, error) { return x509.ParseECPrivateKey(der) },
		x509.ParsePKIXPublicKey,
	}
	for _, parse := range parsers {
		parsed, err := parse(data)
		if err == nil {
			return parsed, nil
		}
	}
	publicKey, _, _, rest, err := ssh.ParseAuthorizedKey(trimmed)
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: unrecognized key artifact", errCertFuzzOracle)
	}
	cryptoKey, ok := publicKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: SSH key has no crypto public key", errCertFuzzOracle)
	}
	return cryptoKey.CryptoPublicKey(), nil
}

func certFuzzMarshalPublicKey(material any) ([]byte, error) {
	if signer, ok := material.(crypto.Signer); ok {
		material = signer.Public()
	}
	der, err := x509.MarshalPKIXPublicKey(material)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal public key: %w", errCertFuzzOracle, err)
	}
	return der, nil
}

func certFuzzDecodeFirstPEM(data []byte) (*pem.Block, []byte, error) {
	if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
		return nil, data, fmt.Errorf("%w: missing PEM begin line", errCertFuzzOracle)
	}
	end := len(data)
	if next := bytes.Index(data, []byte("\n-----BEGIN ")); next >= 0 {
		end = next + 1
	}
	block, rest := pem.Decode(data[:end])
	if block == nil {
		return nil, data, fmt.Errorf("%w: malformed first PEM block", errCertFuzzOracle)
	}
	return block, data[end-len(rest):], nil
}

func certTestPublicKeyDER(tb testing.TB, publicKey any) []byte {
	tb.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		tb.Fatal(err)
	}
	return der
}

type certFuzzFillReader struct{}

func (certFuzzFillReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 'x'
	}
	return len(buffer), nil
}

func executeCertTestWithReader(t *testing.T, input io.Reader, args ...string) (string, string, error) {
	t.Helper()
	root := newRootCmd()
	root.SetIn(input)
	return executeRootCommandStreams(t, root, args...)
}
