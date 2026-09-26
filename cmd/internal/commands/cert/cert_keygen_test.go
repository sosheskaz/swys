package cert_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/sosheskaz-systems/npc/cmd/internal/commands/cert"
	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
	"github.com/sosheskaz-systems/npc/internal/asym"
)

func TestCertKeygenAlgorithms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		algorithm string
		curve     string
		keyType   string
		bits      int
	}{
		{name: "ed25519", algorithm: "ed25519", keyType: "ed25519", bits: 256},
		{name: "p256", algorithm: "p256", keyType: "ecdsa", curve: "P-256", bits: 256},
		{name: "p384", algorithm: "p384", keyType: "ecdsa", curve: "P-384", bits: 384},
		{name: "rsa2048", algorithm: "rsa2048", keyType: "rsa", bits: 2048},
		{name: "rsa4096", algorithm: "rsa4096", keyType: "rsa", bits: 4096},
		{name: "ecdsa-p256", algorithm: "ecdsa-p256", keyType: "ecdsa", curve: "P-256", bits: 256},
		{name: "ecdsa-p384", algorithm: "ecdsa-p384", keyType: "ecdsa", curve: "P-384", bits: 384},
		{name: "rsa-2048", algorithm: "rsa-2048", keyType: "rsa", bits: 2048},
		{name: "rsa-4096", algorithm: "rsa-4096", keyType: "rsa", bits: 4096},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := []string{"cert", "keygen", "--algorithm", test.algorithm}
			stdout, stderr, err := executeRootStreams(t, args...)
			require.NoError(t, err)
			require.Empty(t, stderr, "stderr = %q, want empty", stderr)
			key, err := asym.ParseKey([]byte(stdout))
			require.NoError(t, err)
			info, err := key.Info()
			require.NoError(t, err)
			if !key.IsPrivate() || info.Algorithm != test.keyType || info.Bits != test.bits || info.Curve != test.curve {
				t.Fatalf("generated key info = %+v", info)
			}
		})
	}
}

func TestCertKeygenWritesMatchingPublicSidecars(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		format string
	}{
		{name: "default PKIX PEM"},
		{name: "PKIX DER", format: "pkix-der"},
		{name: "OpenSSH", format: "openssh"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			privatePath := filepath.Join(dir, "private.pem")
			publicPath := filepath.Join(dir, "public.key")
			args := []string{"cert", "keygen", "--output", privatePath, "--public-out", publicPath}
			if test.format != "" {
				args = append(args, "--public-format", test.format)
			}
			if _, _, err := executeRootStreams(t, args...); err != nil {
				t.Fatal(err)
			}

			privateData, err := os.ReadFile(privatePath)
			require.NoError(t, err)
			privateKey, err := asym.ParseKey(privateData)
			if err != nil || !privateKey.IsPrivate() {
				t.Fatalf("private key parse = %v, private = %t", err, err == nil && privateKey.IsPrivate())
			}
			publicData, err := os.ReadFile(publicPath)
			require.NoError(t, err)

			material, err := privateKey.Public()
			require.NoError(t, err)
			wantSSH, err := ssh.NewPublicKey(material)
			require.NoError(t, err)
			if test.format == "openssh" {
				gotSSH, _, _, trailing, err := ssh.ParseAuthorizedKey(publicData)
				if err != nil || len(bytes.TrimSpace(trailing)) != 0 {
					t.Fatalf("parse OpenSSH public key = %v, trailing = %q", err, trailing)
				}
				if !bytes.Equal(gotSSH.Marshal(), wantSSH.Marshal()) {
					t.Fatal("OpenSSH sidecar does not match private key")
				}
				return
			}

			publicKey, err := asym.ParseKey(publicData)
			if err != nil || publicKey.IsPrivate() {
				t.Fatalf("public key parse = %v, private = %t", err, err == nil && publicKey.IsPrivate())
			}
			privateInfo, err := privateKey.Info()
			require.NoError(t, err)
			publicInfo, err := publicKey.Info()
			require.NoError(t, err)
			if privateInfo.PublicKeySHA256Fingerprint != publicInfo.PublicKeySHA256Fingerprint {
				t.Fatal("public sidecar does not match private key")
			}
		})
	}
}

func TestCertKeygenAllowsPrivateStdoutWithPublicSidecar(t *testing.T) {
	t.Parallel()
	publicPath := filepath.Join(t.TempDir(), "public.pem")
	privatePEM, _, err := executeRootStreams(t, "cert", "keygen", "--algorithm", "p256", "--public-out", publicPath)
	require.NoError(t, err)
	privateKey, err := asym.ParseKey([]byte(privatePEM))
	if err != nil || !privateKey.IsPrivate() {
		t.Fatalf("stdout private key parse = %v, private = %t", err, err == nil && privateKey.IsPrivate())
	}
	publicData, err := os.ReadFile(publicPath)
	require.NoError(t, err)
	publicKey, err := asym.ParseKey(publicData)
	if err != nil || publicKey.IsPrivate() {
		t.Fatalf("sidecar public key parse = %v, private = %t", err, err == nil && publicKey.IsPrivate())
	}
}

func TestCertKeygenRejectsInvalidPublicSidecarFlagsBeforeOpeningOutputs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{name: "empty path", args: []string{"cert", "keygen", "--public-out="}},
		{name: "stdout path", args: []string{"cert", "keygen", "--public-out", "-"}},
		{name: "format without path", args: []string{"cert", "keygen", "--public-format", "openssh"}},
		{name: "unknown format", args: []string{"cert", "keygen", "--public-out", "public.pem", "--public-format", "missing"}},
		{name: "private format", args: []string{"cert", "keygen", "--public-out", "public.pem", "--public-format", "pkcs8-pem"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			privatePath := filepath.Join(dir, "private.pem")
			require.NoError(t, os.WriteFile(privatePath, []byte("preserve"), 0o600))
			args := append(append([]string(nil), test.args...), "--output", privatePath)
			if _, _, err := executeRootStreams(t, args...); err == nil {
				t.Fatalf("execute %v succeeded", args)
			}
			data, err := os.ReadFile(privatePath)
			require.NoError(t, err)
			assert.Equal(t, "preserve", string(data), "private output = %q, want preserved", data)
		})
	}
}

func TestCertKeygenRejectsPublicOutputAliasesBeforeOpeningEither(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	t.Run("direct", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "direct.pem")
		_, _, err := executeRootStreams(t, "cert", "keygen", "--output", path, "--public-out", path)
		require.ErrorIs(t, err, cert.ErrKeyOutputCollision, "collision error = %v, want cert.ErrKeyOutputCollision", err)
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("output stat error = %v, want not-exist", statErr)
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		t.Parallel()
		privatePath := filepath.Join(dir, "hard-private.pem")
		publicPath := filepath.Join(dir, "hard-public.pem")
		require.NoError(t, os.WriteFile(privatePath, []byte("preserve"), 0o600))
		if err := os.Link(privatePath, publicPath); err != nil {
			t.Skipf("create hardlink: %v", err)
		}
		_, _, err := executeRootStreams(t, "cert", "keygen", "--output", privatePath, "--public-out", publicPath)
		require.ErrorIs(t, err, cert.ErrKeyOutputCollision, "collision error = %v, want cert.ErrKeyOutputCollision", err)
		data, readErr := os.ReadFile(privatePath)
		if readErr != nil || string(data) != "preserve" {
			t.Fatalf("private output = %q, error = %v; want preserved", data, readErr)
		}
	})

	t.Run("dangling symlink", func(t *testing.T) {
		t.Parallel()
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation requires privileges on some Windows configurations")
		}
		target := filepath.Join(dir, "symlink-target.pem")
		link := filepath.Join(dir, "symlink.pem")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("create symlink: %v", err)
		}
		_, _, err := executeRootStreams(t, "cert", "keygen", "--output", target, "--public-out", link)
		require.ErrorIs(t, err, cert.ErrKeyOutputCollision, "collision error = %v, want cert.ErrKeyOutputCollision", err)
		if _, statErr := os.Stat(target); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("target stat error = %v, want not-exist", statErr)
		}
	})
}

func TestCertKeygenPublicSidecarUsesOrdinaryOverwriteSemantics(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "private.pem")
	publicPath := filepath.Join(dir, "public.pem")
	require.NoError(t, os.WriteFile(publicPath, []byte("replace"), 0o644))
	args := []string{"cert", "keygen", "--output", privatePath, "--public-out", publicPath}
	if runtime.GOOS != "windows" {
		args = append(args, "--mode", "0600")
	}
	if _, _, err := executeRootStreams(t, args...); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(publicPath)
	require.NoError(t, err)
	if key, err := asym.ParseKey(data); err != nil || key.IsPrivate() {
		t.Fatalf("overwritten public key parse = %v, private = %t", err, err == nil && key.IsPrivate())
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(publicPath)
		require.NoError(t, err)
		if got := info.Mode().Perm(); got != 0o644 {
			t.Fatalf("public output mode = %04o, want preserved 0644", got)
		}
	}
}

func TestCertKeygenRetainsPrivateOutputWhenPublicWriteFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "private.pem")
	publicPath := filepath.Join(dir, "missing", "public.pem")
	_, _, err := executeRootStreams(t, "cert", "keygen", "--output", privatePath, "--public-out", publicPath)
	if err == nil || !strings.Contains(err.Error(), "private key retained") || !strings.Contains(err.Error(), strconv.Quote(privatePath)) {
		t.Fatalf("public output error = %v, want retained private-key path", err)
	}
	privateData, readErr := os.ReadFile(privatePath)
	require.NoError(t, readErr)
	if key, parseErr := asym.ParseKey(privateData); parseErr != nil || !key.IsPrivate() {
		t.Fatalf("retained private key parse = %v, private = %t", parseErr, parseErr == nil && key.IsPrivate())
	}
}

func TestCertKeygenOutputUsesPrivatePermissions(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "private.pem")
	if _, _, err := executeRootStreams(t, "cert", "keygen", "--output", path); err != nil {
		t.Fatal(err)
	}
	testcmd.AssertPrivateOutput(t, path)
}

func TestCertKeygenUnknownAlgorithmPreservesErrorIdentity(t *testing.T) {
	t.Parallel()
	_, _, err := executeRootStreams(t, "cert", "keygen", "--algorithm", "missing")
	require.ErrorIs(t, err, cert.ErrUnknownKeyAlgorithm)
	require.ErrorContains(t, err, "ed25519, p256, p384, rsa2048, rsa4096")
}

func TestCertKeygenRejectsUnknownAlgorithmBeforeOutputOpen(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "existing")
	require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
	_, _, err := executeRootStreams(t, "cert", "keygen", "--algorithm", "missing", "--output", path)
	require.ErrorIs(t, err, cert.ErrUnknownKeyAlgorithm)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("preserve"), data)
}

func TestCertKeygenRejectsInvalidSelectionsBeforeOutput(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"cert", "keygen", "--algorithm="},
		{"cert", "keygen", "unexpected"},
	} {
		path := filepath.Join(t.TempDir(), "existing.key")
		require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
		_, _, err := executeRootStreams(t, append(args, "--output", path)...)
		require.Error(t, err, "args %v", args)
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, []byte("preserve"), data)
	}
}
