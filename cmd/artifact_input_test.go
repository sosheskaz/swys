package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestReadArtifactBoundaries(t *testing.T) {
	t.Parallel()
	for _, size := range []int{0, 1, 31, 32, 33, 4096} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			t.Parallel()
			input := bytes.NewReader(bytes.Repeat([]byte{'x'}, size))
			data, err := readArtifact(input, 32)
			if size > 32 {
				if !errors.Is(err, errArtifactTooLarge) || data != nil {
					t.Fatalf("data = %v, err = %v", data, err)
				}
				if input.Len() != size-33 {
					t.Fatalf("read beyond overflow probe: %d bytes remain", input.Len())
				}
			} else if err != nil || len(data) != size {
				t.Fatalf("length = %d, err = %v", len(data), err)
			}
		})
	}
}

func TestReadArtifactPreservesIOErrors(t *testing.T) {
	t.Parallel()
	input := io.MultiReader(strings.NewReader("partial"), keyFailingReader{err: errKeyTestReadFailed})
	data, err := readArtifact(input, 32)
	if !errors.Is(err, errKeyTestReadFailed) || data != nil {
		t.Fatalf("data = %v, err = %v", data, err)
	}
	_, err = readArtifactFile(filepath.Join(t.TempDir(), "missing"), 32)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	_, err = readArtifactFile(t.TempDir(), 32)
	if err == nil {
		t.Fatal("directory read succeeded")
	}
}

func TestArtifactCommandsRejectOversizedInputs(t *testing.T) {
	identity := createNetworkTestIdentity(t)
	keyPath := writeOversizedArtifact(t, maxKeyArtifactBytes)
	certPath := writeOversizedArtifact(t, maxCertificateArtifactBytes)
	aesPath := writeOversizedArtifact(t, maxAESKeyBytes)
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
			args := []string{"net", operation, "tls", "127.0.0.1:0"}
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
			stdout, _, err := executeRootStreams(t, test.args...)
			if !errors.Is(err, errArtifactTooLarge) || stdout != "" {
				t.Fatalf("stdout = %q, err = %v", stdout, err)
			}
		})
	}
}

func TestArtifactCommandsBoundStdinAndPreserveFaults(t *testing.T) {
	for _, test := range []struct {
		name  string
		args  []string
		limit int64
	}{
		{"key", []string{"key", "inspect"}, maxKeyArtifactBytes},
		{"certificate", []string{"cert", "inspect"}, maxCertificateArtifactBytes},
		{"create", []string{"cert", "create", "--key", "-"}, maxKeyArtifactBytes},
		{"csr", []string{"cert", "csr", "--key", "-"}, maxKeyArtifactBytes},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := bytes.NewReader(bytes.Repeat([]byte{'x'}, int(test.limit)+2))
			stdout, stderr, err := executeRootStreamsWithInput(t, input, test.args...)
			if !errors.Is(err, errArtifactTooLarge) || input.Len() != 1 || stdout != "" {
				t.Fatalf("remaining = %d, stdout = %q, stderr = %q, err = %v", input.Len(), stdout, stderr, err)
			}
			_, _, err = executeRootStreamsWithInput(t, keyFailingReader{err: errKeyTestReadFailed}, test.args...)
			if !errors.Is(err, errKeyTestReadFailed) {
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

func BenchmarkReadArtifact(b *testing.B) {
	for _, size := range []int{4096, 1 << 20, 16 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			data := bytes.Repeat([]byte{'x'}, size)
			b.ReportAllocs()
			for b.Loop() {
				_, err := readArtifact(bytes.NewReader(data), maxKeyArtifactBytes)
				if err != nil && !errors.Is(err, errArtifactTooLarge) {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestArtifactCommandsAcceptExactLimits(t *testing.T) {
	identity := createNetworkTestIdentity(t)
	for _, test := range []struct {
		name  string
		path  string
		args  []string
		limit int64
	}{
		{"key", identity.serverKey, []string{"key", "inspect"}, maxKeyArtifactBytes},
		{"certificate", identity.caCert, []string{"cert", "inspect"}, maxCertificateArtifactBytes},
	} {
		t.Run(test.name, func(t *testing.T) {
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
			path := filepath.Join(t.TempDir(), "aes-key")
			if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, size), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err := executeRootStreams(t, "aes", "encrypt", "hello", "--keyfile", path)
			valid := size == 16 || size == 24 || size == 32
			if (err == nil) != valid || errors.Is(err, errArtifactTooLarge) {
				t.Fatalf("key size %d: %v", size, err)
			}
		})
	}
}
