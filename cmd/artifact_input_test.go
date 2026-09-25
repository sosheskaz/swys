package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"testing/iotest"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/artifact"
	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
)

var errArtifactRootReadFailure = errors.New("read failed")

func TestArtifactCommandsRejectOversizedInputs(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	keyPath := writeOversizedArtifact(t, artifact.MaxKeyBytes)
	certPath := writeOversizedArtifact(t, artifact.MaxCertificateBytes)
	aesPath := writeOversizedArtifact(t, artifact.MaxAESKeyBytes)
	tests := []struct {
		name string
		args []string
	}{
		{"key inspect", []string{"key", "inspect", "--input", keyPath}},
		{"key public", []string{"key", "public", "--input", keyPath}},
		{"key convert", []string{"key", "convert", "--to", "pkix-pem", "--input", keyPath}},
		{"cert inspect", []string{"cert", "inspect", "--input", certPath}},
		{"cert create key", []string{"cert", "create", "--key", keyPath}},
		{"cert csr key", []string{"cert", "csr", "--key", keyPath}},
		{"cert issuer cert", []string{"cert", "create", "--key", identity.serverKey, "--issuer-cert", certPath, "--issuer-key", identity.serverKey}},
		{"cert issuer key", []string{"cert", "create", "--key", identity.serverKey, "--issuer-cert", identity.caCert, "--issuer-key", keyPath}},
		{"aes encrypt", []string{"aes", "encrypt", "hello", "--keyfile", aesPath}},
		{"aes decrypt", []string{"aes", "decrypt", "hello", "--keyfile", aesPath}},
	}
	for _, operation := range []string{"connect", "listen"} {
		for _, artifact := range []struct{ name, path string }{{"ca", certPath}, {"cert", certPath}, {"key", keyPath}} {
			args := []string{"net", operation, "--tls", "127.0.0.1:0"}
			switch artifact.name {
			case "ca":
				args = append(args, "--ca", artifact.path, "--cert", identity.serverCert, "--key", identity.serverKey)
			case "cert":
				args = append(args, "--cert", artifact.path, "--key", identity.serverKey)
			case "key":
				args = append(args, "--cert", identity.serverCert, "--key", artifact.path)
			}
			tests = append(tests, struct {
				name string
				args []string
			}{operation + " " + artifact.name, args})
		}
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			stdout, _, err := executeRootStreams(t, test.args...)
			if !errors.Is(err, artifact.ErrTooLarge) || stdout != "" {
				t.Fatalf("stdout = %q, err = %v", stdout, err)
			}
		})
	}
}

func TestArtifactCommandsBoundStdinAndPreserveFaults(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		args  []string
		limit int64
	}{
		{"key", []string{"key", "inspect"}, artifact.MaxKeyBytes},
		{"certificate", []string{"cert", "inspect"}, artifact.MaxCertificateBytes},
		{"create", []string{"cert", "create", "--key", "-"}, artifact.MaxKeyBytes},
		{"csr", []string{"cert", "csr", "--key", "-"}, artifact.MaxKeyBytes},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := bytes.NewReader(bytes.Repeat([]byte{'x'}, int(test.limit)+2))
			stdout, stderr, err := executeRootStreamsWithInput(t, input, test.args...)
			if !errors.Is(err, artifact.ErrTooLarge) || input.Len() != 1 || stdout != "" {
				t.Fatalf("remaining = %d, stdout = %q, stderr = %q, err = %v", input.Len(), stdout, stderr, err)
			}
			_, _, err = executeRootStreamsWithInput(t, iotest.ErrReader(errArtifactRootReadFailure), test.args...)
			if !errors.Is(err, errArtifactRootReadFailure) {
				t.Fatalf("read fault: %v", err)
			}
		})
	}
}

func writeOversizedArtifact(t *testing.T, limit int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "oversized")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, int(limit)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestArtifactCommandsAcceptExactLimits(t *testing.T) {
	t.Parallel()
	identity := createNetworkTestIdentity(t)
	for _, test := range []struct {
		name  string
		path  string
		args  []string
		limit int64
	}{
		{"key", identity.serverKey, []string{"key", "inspect"}, artifact.MaxKeyBytes},
		{"certificate", identity.caCert, []string{"cert", "inspect"}, artifact.MaxCertificateBytes},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(test.path)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, bytes.Repeat([]byte{'\n'}, int(test.limit)-len(data))...)
			stdout, stderr, err := executeRootStreamsWithInput(t, bytes.NewReader(data), test.args...)
			if err != nil || stdout == "" {
				t.Fatalf("stdout = %q, stderr = %q, err = %v", stdout, stderr, err)
			}
		})
	}
	for _, size := range []int{0, 1, 16, 24, 31, 32} {
		t.Run("aes"+strconv.Itoa(size), func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "aes-key")
			if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, size), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err := executeRootStreams(t, "aes", "encrypt", "hello", "--keyfile", path)
			valid := size == 16 || size == 32
			if (err == nil) != valid || errors.Is(err, artifact.ErrTooLarge) {
				t.Fatalf("key size %d: %v", size, err)
			}
		})
	}
}

func executeRootStreamsWithInput(t *testing.T, input io.Reader, args ...string) (string, string, error) {
	t.Helper()
	stdout, stderr, err := testcmd.RunStreams(t, NewCommand(), input, args...)
	return string(stdout), string(stderr), err
}

type networkTestIdentity struct {
	caCert     string
	serverCert string
	serverKey  string
	clientCert string
	clientKey  string
}

func createNetworkTestIdentity(t *testing.T) networkTestIdentity {
	t.Helper()
	identity := testcmd.CreateNetworkIdentity(t, NewCommand)
	return networkTestIdentity{
		caCert:     identity.CACert,
		serverCert: identity.ServerCert,
		serverKey:  identity.ServerKey,
		clientCert: identity.ClientCert,
		clientKey:  identity.ClientKey,
	}
}
