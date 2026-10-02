package cert_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/internal/asym"
)

func TestCertCreateBuildsInspectableProfiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	selfKey := filepath.Join(dir, "self.key")
	selfCert := filepath.Join(dir, "self.crt")
	generateTestKey(t, "ed25519", selfKey)
	before := time.Now()
	if _, _, err := executeRootStreams(
		t,
		"cert", "create", "--key", selfKey, "--output", selfCert,
	); err != nil {
		t.Fatal(err)
	}
	self := readSingleCertificate(t, selfCert)
	if self.Subject.CommonName != "localhost" || len(self.DNSNames) != 1 || self.DNSNames[0] != "localhost" {
		t.Fatalf("default leaf = subject:%q DNS:%v", self.Subject.CommonName, self.DNSNames)
	}
	if err := self.VerifyHostname("localhost"); err != nil {
		t.Fatalf("verify default leaf hostname: %v", err)
	}
	require.Len(t, self.ExtKeyUsage, 2, "default leaf EKU = %v", self.ExtKeyUsage)
	wantNotAfter := before.UTC().Truncate(time.Second).Add(30 * 24 * time.Hour)
	if delta := self.NotAfter.Sub(wantNotAfter); delta < -time.Second || delta > time.Second {
		t.Fatalf("default leaf expiration = %s, want approximately 30 days", self.NotAfter)
	}

	caKey := filepath.Join(dir, "ca.key")
	caCert := filepath.Join(dir, "ca.crt")
	generateTestKey(t, "ed25519", caKey)
	if _, _, err := executeRootStreams(
		t,
		"cert", "create", "--ca", "--subject", "CN=test-ca",
		"--key", caKey, "--output", caCert,
	); err != nil {
		t.Fatal(err)
	}
	ca := readSingleCertificate(t, caCert)
	if !ca.IsCA || ca.Subject.CommonName != "test-ca" {
		t.Fatalf("CA = IsCA:%t subject:%q", ca.IsCA, ca.Subject.CommonName)
	}
	if _, _, err := executeRootStreams(t, "cert", "key-inspect", "--input", caKey); err != nil {
		t.Fatalf("inspect CA key: %v", err)
	}
	inspected, _, err := executeRootStreams(t, "cert", "inspect", "--input", caCert)
	require.NoError(t, err, "inspect generated certificate: %v", err)
	if !strings.Contains(inspected, "test-ca") {
		t.Fatalf("inspection output = %q, want test-ca", inspected)
	}

	serverKey := filepath.Join(dir, "server.key")
	serverCert := filepath.Join(dir, "server.crt")
	generateTestKey(t, "ed25519", serverKey)
	if _, _, err := executeRootStreams(
		t,
		"cert", "create", "--dns", "localhost", "--ip", "127.0.0.1",
		"--server-only", "--key", serverKey,
		"--issuer-cert", caCert, "--issuer-key", caKey,
		"--output", serverCert,
	); err != nil {
		t.Fatal(err)
	}
	server := readSingleCertificate(t, serverCert)
	if server.Subject.CommonName != "localhost" || len(server.DNSNames) != 1 || server.DNSNames[0] != "localhost" {
		t.Fatalf("server subject/SANs = %q/%v", server.Subject.CommonName, server.DNSNames)
	}
	if len(server.ExtKeyUsage) != 1 || server.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("server EKU = %v", server.ExtKeyUsage)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := server.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "localhost",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("verify generated server certificate: %v", err)
	}

	clientKey := filepath.Join(dir, "client.key")
	clientCert := filepath.Join(dir, "client.crt")
	generateTestKey(t, "p256", clientKey)
	if _, _, err := executeRootStreams(
		t,
		"cert", "create", "--subject", "CN=client", "--client-only",
		"--key", clientKey, "--issuer-cert", caCert, "--issuer-key", caKey,
		"--output", clientCert,
	); err != nil {
		t.Fatal(err)
	}
	client := readSingleCertificate(t, clientCert)
	require.Empty(t, client.DNSNames, "explicit client DNS SANs = %v, want none", client.DNSNames)
	if len(client.ExtKeyUsage) != 1 || client.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("client EKU = %v", client.ExtKeyUsage)
	}
}

func TestCertCreateDefaultsExplicitServerSubjectToDNSSAN(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "server.key")
	certPath := filepath.Join(dir, "server.crt")
	generateTestKey(t, "ed25519", keyPath)

	if _, _, err := executeRootStreams(
		t,
		"cert", "create", "--subject", "CN=service.internal",
		"--key", keyPath, "--output", certPath,
	); err != nil {
		t.Fatal(err)
	}
	cert := readSingleCertificate(t, certPath)
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "service.internal" {
		t.Fatalf("explicit server DNS SANs = %v, want [service.internal]", cert.DNSNames)
	}
	if err := cert.VerifyHostname("service.internal"); err != nil {
		t.Fatalf("verify explicit server hostname: %v", err)
	}
}

func TestCertCreateDefaultsIPSubjectToIPSAN(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "server.key")
	certPath := filepath.Join(dir, "server.crt")
	generateTestKey(t, "ed25519", keyPath)

	if _, _, err := executeRootStreams(
		t,
		"cert", "create", "--subject", "CN=127.0.0.1",
		"--key", keyPath, "--output", certPath,
	); err != nil {
		t.Fatal(err)
	}
	cert := readSingleCertificate(t, certPath)
	require.Empty(t, cert.DNSNames, "IP-subject DNS SANs = %v, want none", cert.DNSNames)
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("IP-subject IP SANs = %v, want [127.0.0.1]", cert.IPAddresses)
	}
	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("verify explicit server IP: %v", err)
	}
}

func TestCertCreateClientOnlyWithoutSubjectOmitsSANs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "client.key")
	certPath := filepath.Join(dir, "client.crt")
	generateTestKey(t, "ed25519", keyPath)

	if _, _, err := executeRootStreams(
		t,
		"cert", "create", "--client-only",
		"--key", keyPath, "--output", certPath,
	); err != nil {
		t.Fatal(err)
	}
	cert := readSingleCertificate(t, certPath)
	if cert.Subject.CommonName != "localhost" {
		t.Fatalf("client-only subject = %q, want localhost", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 {
		t.Fatalf("client-only SANs = DNS:%v IP:%v, want none", cert.DNSNames, cert.IPAddresses)
	}
}

func TestCertCreateBindsEitherIssuerArtifactToStdin(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	caKey := filepath.Join(dir, "ca.key")
	caCert := filepath.Join(dir, "ca.crt")
	subjectKey := filepath.Join(dir, "subject.key")
	generateTestKey(t, "ed25519", caKey)
	if _, _, err := executeRootStreams(
		t,
		"cert", "create", "--ca", "--subject", "CN=ca", "--key", caKey, "--output", caCert,
	); err != nil {
		t.Fatal(err)
	}
	generateTestKey(t, "ed25519", subjectKey)
	tests := []struct {
		name      string
		inputPath string
		args      []string
	}{
		{
			name:      "issuer certificate",
			inputPath: caCert,
			args:      []string{"--issuer-cert", "-", "--issuer-key", caKey},
		},
		{
			name:      "issuer key",
			inputPath: caKey,
			args:      []string{"--issuer-cert", caCert, "--issuer-key", "-"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output := filepath.Join(dir, strings.ReplaceAll(test.name, " ", "-")+".crt")
			args := []string{
				"cert", "create", "--subject", "CN=leaf", "--key", subjectKey,
				"--input", test.inputPath, "--output", output,
			}
			args = append(args, test.args...)
			if _, _, err := executeRootStreams(t, args...); err != nil {
				t.Fatal(err)
			}
			if err := readSingleCertificate(t, output).CheckSignatureFrom(readSingleCertificate(t, caCert)); err != nil {
				t.Fatalf("check issuer signature: %v", err)
			}
		})
	}
}

func TestCertCSRRoundTripsWrappedStdinKey(t *testing.T) {
	t.Parallel()
	privatePEM, _, err := executeRootStreams(t, "cert", "keygen", "--algorithm", "p384")
	require.NoError(t, err)
	dir := t.TempDir()
	wrappedPath := filepath.Join(dir, "key.b64")
	wrapped := base64.StdEncoding.EncodeToString([]byte(privatePEM))
	require.NoError(t, os.WriteFile(wrappedPath, []byte(wrapped), 0o600))
	output, _, err := executeRootStreams(
		t,
		"cert", "csr", "--subject", "CN=service.internal", "--dns", "service.internal",
		"--ip", "192.0.2.10", "--key", "-", "--input", wrappedPath,
		"--input-encoding", "base64",
	)
	require.NoError(t, err)
	block, rest := pem.Decode([]byte(output))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("CSR PEM block = %#v, trailing = %q", block, rest)
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	if err := request.CheckSignature(); err != nil {
		t.Fatalf("check CSR signature: %v", err)
	}
	if request.Subject.CommonName != "service.internal" || len(request.DNSNames) != 1 || request.DNSNames[0] != "service.internal" {
		t.Fatalf("CSR subject/SANs = %q/%v", request.Subject.CommonName, request.DNSNames)
	}
}

func TestCertCSRDefaultsToLocalhostSAN(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	if _, _, err := executeRootStreams(t, "cert", "keygen", "--output", keyPath); err != nil {
		t.Fatal(err)
	}
	output, _, err := executeRootStreams(t, "cert", "csr", "--key", keyPath)
	require.NoError(t, err)
	block, rest := pem.Decode([]byte(output))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("CSR PEM block = %#v, trailing = %q", block, rest)
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	if request.Subject.CommonName != "localhost" || len(request.DNSNames) != 1 || request.DNSNames[0] != "localhost" {
		t.Fatalf("default CSR = subject:%q DNS:%v", request.Subject.CommonName, request.DNSNames)
	}
}

func TestCertCreateRejectsUnsafeFlagsBeforeOpeningOutput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.pem")
	keyPath := filepath.Join(dir, "key.pem")
	generateTestKey(t, "ed25519", keyPath)
	require.NoError(t, os.WriteFile(inputPath, []byte("input"), 0o600))
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing key selection", args: []string{"cert", "create", "--subject", "CN=leaf"}},
		{name: "removed key-out", args: []string{"cert", "create", "--subject", "CN=leaf", "--key", keyPath, "--key-out", "new.key"}},
		{name: "empty existing key", args: []string{"cert", "create", "--subject", "CN=leaf", "--key="}},
		{name: "CA missing subject", args: []string{"cert", "create", "--ca", "--key", keyPath}},
		{name: "CA with SAN", args: []string{"cert", "create", "--ca", "--subject", "CN=ca", "--dns", "ca.test", "--key", keyPath}},
		{name: "incomplete issuer", args: []string{"cert", "create", "--subject", "CN=leaf", "--key", keyPath, "--issuer-cert", "ca.crt"}},
		{
			name: "empty issuer certificate",
			args: []string{
				"cert", "create", "--subject", "CN=leaf", "--key", keyPath,
				"--issuer-cert=", "--issuer-key", "ca.key",
			},
		},
		{name: "empty issuer key", args: []string{"cert", "create", "--subject", "CN=leaf", "--key", keyPath, "--issuer-cert", "ca.crt", "--issuer-key="}},
		{name: "zero days", args: []string{"cert", "create", "--subject", "CN=leaf", "--days", "0", "--key", keyPath}},
		{name: "negative days", args: []string{"cert", "create", "--subject", "CN=leaf", "--days", "-1", "--key", keyPath}},
		{name: "full DN", args: []string{"cert", "create", "--subject", "CN=leaf,O=npc", "--key", keyPath}},
		{name: "bad IP", args: []string{"cert", "create", "--subject", "CN=leaf", "--ip", "not-an-ip", "--key", keyPath}},
		{name: "unused input", args: []string{"cert", "create", "--subject", "CN=leaf", "--key", keyPath, "--input", inputPath}},
		{name: "unused input encoding", args: []string{"cert", "create", "--subject", "CN=leaf", "--key", keyPath, "--input-encoding", "base64"}},
		{name: "multiple stdin owners", args: []string{"cert", "create", "--subject", "CN=leaf", "--key", "-", "--issuer-cert", "-", "--issuer-key", "ca.key"}},
		{name: "CSR missing key", args: []string{"cert", "csr", "--subject", "CN=leaf"}},
		{name: "CSR empty key", args: []string{"cert", "csr", "--subject", "CN=leaf", "--key="}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			outputPath := filepath.Join(t.TempDir(), "certificate.pem")
			require.NoError(t, os.WriteFile(outputPath, []byte("preserve"), 0o600))
			args := append(append([]string(nil), test.args...), "--output", outputPath)
			if _, _, err := executeRootStreams(t, args...); err == nil {
				t.Fatalf("execute %v succeeded", args)
			}
			data, err := os.ReadFile(outputPath)
			require.NoError(t, err)
			assert.Equal(t, "preserve", string(data), "output = %q, want preserved content", data)
		})
	}
}

func TestCertCreateProtectsInputPaths(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	inputKey := filepath.Join(dir, "subject.key")
	generateTestKey(t, "ed25519", inputKey)
	wantKey, err := os.ReadFile(inputKey)
	require.NoError(t, err)
	_, _, err = executeRootStreams(
		t,
		"cert", "create", "--subject", "CN=leaf", "--key", inputKey, "--output", inputKey,
	)
	require.ErrorIs(t, err, errCertificatePathCollision, "same input/output error = %v, want errCertificatePathCollision", err)
	gotKey, err := os.ReadFile(inputKey)
	require.NoError(t, err)
	if !bytes.Equal(gotKey, wantKey) {
		t.Fatal("input key was modified")
	}
}

func TestCertCreateDefersMissingOutputParentToOutputOpen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	if _, _, err := executeRootStreams(t, "cert", "keygen", "--output", keyPath); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(dir, "missing", "cert.pem")
	_, _, err := executeRootStreams(
		t,
		"cert", "create", "--key", keyPath, "--output", outputPath,
	)
	if err == nil || !strings.Contains(err.Error(), "open output") {
		t.Fatalf("missing parent error = %v, want output-open error", err)
	}
	if strings.Contains(err.Error(), "resolve parent") {
		t.Fatalf("missing parent error = %v, should not come from collision detection", err)
	}
}

func TestCertCreateRejectsIssuerMismatchAndTrailingCertificateData(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	caKey := filepath.Join(dir, "ca.key")
	caCert := filepath.Join(dir, "ca.crt")
	generateTestKey(t, "ed25519", caKey)
	if _, _, err := executeRootStreams(
		t,
		"cert", "create", "--ca", "--subject", "CN=ca", "--key", caKey, "--output", caCert,
	); err != nil {
		t.Fatal(err)
	}
	wrongKey := filepath.Join(dir, "wrong.key")
	generateTestKey(t, "ed25519", wrongKey)
	leafKey := filepath.Join(dir, "leaf.key")
	generateTestKey(t, "ed25519", leafKey)
	_, _, err := executeRootStreams(t, "cert", "create", "--subject", "CN=leaf", "--key", caCert)
	if !errors.Is(err, asym.ErrUnexpectedKeyPEMType) || !strings.Contains(err.Error(), certificatePEMType) {
		t.Fatalf("certificate-as-key error = %v, want block type and ErrUnexpectedKeyPEMType", err)
	}
	publicKey := filepath.Join(dir, "public.key")
	if _, _, err := executeRootStreams(t, "cert", "key-public", "--input", caKey, "--output", publicKey); err != nil {
		t.Fatal(err)
	}
	_, _, err = executeRootStreams(t, "cert", "csr", "--subject", "CN=leaf", "--key", publicKey)
	require.ErrorIs(t, err, asym.ErrPrivateKeyRequired, "public CSR key error = %v, want ErrPrivateKeyRequired", err)

	_, _, err = executeRootStreams(
		t,
		"cert", "create", "--subject", "CN=leaf", "--key", leafKey,
		"--issuer-cert", caCert, "--issuer-key", wrongKey,
	)
	require.ErrorIs(t, err, asym.ErrIssuerKeyMismatch, "issuer mismatch error = %v, want ErrIssuerKeyMismatch", err)
	if !strings.Contains(err.Error(), "--issuer-cert") || !strings.Contains(err.Error(), "--issuer-key") {
		t.Fatalf("issuer mismatch error = %v, want both flag names", err)
	}

	certData, err := os.ReadFile(caCert)
	require.NoError(t, err)
	trailingCert := filepath.Join(dir, "trailing.crt")
	require.NoError(t, os.WriteFile(trailingCert, append(certData, []byte("trailing")...), 0o600))
	_, _, err = executeRootStreams(
		t,
		"cert", "create", "--subject", "CN=leaf", "--key", leafKey,
		"--issuer-cert", trailingCert, "--issuer-key", caKey,
	)
	require.ErrorIs(t, err, errTrailingCertificateData, "trailing issuer error = %v, want errTrailingCertificateData", err)

	multipleCerts := filepath.Join(dir, "multiple.crt")
	require.NoError(t, os.WriteFile(multipleCerts, append(bytes.Clone(certData), certData...), 0o600))
	_, _, err = executeRootStreams(
		t,
		"cert", "create", "--subject", "CN=leaf", "--key", leafKey,
		"--issuer-cert", multipleCerts, "--issuer-key", caKey,
	)
	require.ErrorIs(t, err, errTrailingCertificateData, "multiple issuer error = %v, want errTrailingCertificateData", err)
}

func TestCertCreateEnablesMutualTLSHandshake(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	caKey := filepath.Join(dir, "ca.key")
	caCert := filepath.Join(dir, "ca.crt")
	serverKey := filepath.Join(dir, "server.key")
	serverCert := filepath.Join(dir, "server.crt")
	clientKey := filepath.Join(dir, "client.key")
	clientCert := filepath.Join(dir, "client.crt")
	generateTestKey(t, "ed25519", caKey)
	generateTestKey(t, "ed25519", serverKey)
	generateTestKey(t, "ed25519", clientKey)

	commands := [][]string{
		{"cert", "create", "--ca", "--subject", "CN=test-ca", "--key", caKey, "--output", caCert},
		{"cert", "create", "--dns", "localhost", "--server-only", "--key", serverKey, "--issuer-cert", caCert, "--issuer-key", caKey, "--output", serverCert},
		{"cert", "create", "--subject", "CN=client", "--client-only", "--key", clientKey, "--issuer-cert", caCert, "--issuer-key", caKey, "--output", clientCert},
	}
	for _, args := range commands {
		if _, _, err := executeRootStreams(t, args...); err != nil {
			t.Fatalf("execute %v: %v", args, err)
		}
	}

	serverIdentity, err := tls.LoadX509KeyPair(serverCert, serverKey)
	require.NoError(t, err)
	clientIdentity, err := tls.LoadX509KeyPair(clientCert, clientKey)
	require.NoError(t, err)
	caPEM, err := os.ReadFile(caCert)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("append generated CA")
	}

	serverConn, clientConn := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	require.NoError(t, serverConn.SetDeadline(deadline))
	require.NoError(t, clientConn.SetDeadline(deadline))
	serverTLS := tls.Server(serverConn, &tls.Config{
		Certificates: []tls.Certificate{serverIdentity},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
		MinVersion:   tls.VersionTLS12,
	})
	clientTLS := tls.Client(clientConn, &tls.Config{
		Certificates: []tls.Certificate{clientIdentity},
		RootCAs:      roots,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	})
	t.Cleanup(func() {
		if err := serverConn.Close(); err != nil {
			t.Errorf("close server connection: %v", err)
		}
		if err := clientConn.Close(); err != nil {
			t.Errorf("close client connection: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	serverErr := make(chan error, 1)
	go func() { serverErr <- serverTLS.HandshakeContext(ctx) }()
	if err := clientTLS.HandshakeContext(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if len(clientTLS.ConnectionState().VerifiedChains) == 0 || len(serverTLS.ConnectionState().VerifiedChains) == 0 {
		t.Fatal("mTLS handshake did not verify both peer chains")
	}
}

func readSingleCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("certificate PEM block = %#v, trailing = %q", block, rest)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func generateTestKey(t *testing.T, algorithm, path string) {
	t.Helper()
	if _, _, err := executeRootStreams(t, "cert", "keygen", "--algorithm", algorithm, "--output", path); err != nil {
		t.Fatalf("generate %s key: %v", algorithm, err)
	}
}

func TestCertificateCreationPreservesOutputOnKeyFailure(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"create", "csr"} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			for _, failure := range []string{"missing", "malformed"} {
				t.Run(failure, func(t *testing.T) {
					t.Parallel()
					dir := t.TempDir()
					key := filepath.Join(dir, "private.key")
					wantErr := os.ErrNotExist
					if failure == "malformed" {
						require.NoError(t, os.WriteFile(key, []byte("not a key"), 0o600))
						wantErr = asym.ErrMalformedKey
					}
					output := filepath.Join(dir, "artifact.pem")
					require.NoError(t, os.WriteFile(output, []byte("sentinel"), 0o600))
					_, _, err := executeRootStreams(t, "cert", operation, "--key", key, "--output", output)
					require.ErrorIs(t, err, wantErr)
					remaining, err := os.ReadFile(output)
					require.NoError(t, err)
					assert.Equal(t, "sentinel", string(remaining))
				})
			}
		})
	}
}
