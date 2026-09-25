package key_test

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	keycommand "github.com/sosheskaz-systems/npc/cmd/internal/commands/key"
	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
	"github.com/sosheskaz-systems/npc/internal/asym"
)

var errKeyTestReadFailed = errors.New("read failed")

func TestKeyGenerateAlgorithms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		algorithm string
		curve     string
		keyType   string
		bits      int
		bytes     int
	}{
		{name: "ed25519", algorithm: "ed25519", keyType: "ed25519", bits: 256},
		{name: "p256", algorithm: "p256", keyType: "ecdsa", curve: "P-256", bits: 256},
		{name: "p384", algorithm: "p384", keyType: "ecdsa", curve: "P-384", bits: 384},
		{name: "rsa2048", algorithm: "rsa2048", keyType: "rsa", bits: 2048},
		{name: "rsa4096", algorithm: "rsa4096", keyType: "rsa", bits: 4096},
		{name: "aes128", algorithm: "aes128", bytes: 16},
		{name: "aes256", algorithm: "aes256", bytes: 32},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := []string{"key", "generate", test.algorithm}
			stdout, stderr, err := executeRootStreams(t, args...)
			require.NoError(t, err)
			require.Empty(t, stderr, "stderr = %q, want empty", stderr)
			if test.bytes != 0 {
				if len(stdout) != test.bytes {
					t.Fatalf("AES key length = %d, want %d", len(stdout), test.bytes)
				}
				return
			}
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

func TestKeyGenerateWritesMatchingPublicSidecars(t *testing.T) {
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
			args := []string{"key", "generate", "ed25519", "--output", privatePath, "--public-out", publicPath}
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

func TestKeyGenerateAllowsPrivateStdoutWithPublicSidecar(t *testing.T) {
	t.Parallel()
	publicPath := filepath.Join(t.TempDir(), "public.pem")
	privatePEM, _, err := executeRootStreams(t, "key", "generate", "p256", "--public-out", publicPath)
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

func TestKeyGenerateRejectsInvalidPublicSidecarFlagsBeforeOpeningOutputs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{name: "AES", args: []string{"key", "generate", "aes256", "--public-out", "public.pem"}},
		{name: "empty path", args: []string{"key", "generate", "ed25519", "--public-out="}},
		{name: "stdout path", args: []string{"key", "generate", "ed25519", "--public-out", "-"}},
		{name: "format without path", args: []string{"key", "generate", "ed25519", "--public-format", "openssh"}},
		{name: "unknown format", args: []string{"key", "generate", "ed25519", "--public-out", "public.pem", "--public-format", "missing"}},
		{name: "private format", args: []string{"key", "generate", "ed25519", "--public-out", "public.pem", "--public-format", "pkcs8-pem"}},
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

func TestKeyGenerateRejectsPublicOutputAliasesBeforeOpeningEither(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	t.Run("direct", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "direct.pem")
		_, _, err := executeRootStreams(t, "key", "generate", "ed25519", "--output", path, "--public-out", path)
		require.ErrorIs(t, err, errKeyOutputCollision, "collision error = %v, want errKeyOutputCollision", err)
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
		_, _, err := executeRootStreams(t, "key", "generate", "ed25519", "--output", privatePath, "--public-out", publicPath)
		require.ErrorIs(t, err, errKeyOutputCollision, "collision error = %v, want errKeyOutputCollision", err)
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
		_, _, err := executeRootStreams(t, "key", "generate", "ed25519", "--output", target, "--public-out", link)
		require.ErrorIs(t, err, errKeyOutputCollision, "collision error = %v, want errKeyOutputCollision", err)
		if _, statErr := os.Stat(target); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("target stat error = %v, want not-exist", statErr)
		}
	})
}

func TestKeyGeneratePublicSidecarUsesOrdinaryOverwriteSemantics(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "private.pem")
	publicPath := filepath.Join(dir, "public.pem")
	require.NoError(t, os.WriteFile(publicPath, []byte("replace"), 0o644))
	args := []string{"key", "generate", "ed25519", "--output", privatePath, "--public-out", publicPath}
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

func TestKeyGenerateRetainsPrivateOutputWhenPublicWriteFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "private.pem")
	publicPath := filepath.Join(dir, "missing", "public.pem")
	_, _, err := executeRootStreams(t, "key", "generate", "ed25519", "--output", privatePath, "--public-out", publicPath)
	if err == nil || !strings.Contains(err.Error(), "private key retained") || !strings.Contains(err.Error(), strconv.Quote(privatePath)) {
		t.Fatalf("public output error = %v, want retained private-key path", err)
	}
	privateData, readErr := os.ReadFile(privatePath)
	require.NoError(t, readErr)
	if key, parseErr := asym.ParseKey(privateData); parseErr != nil || !key.IsPrivate() {
		t.Fatalf("retained private key parse = %v, private = %t", parseErr, parseErr == nil && key.IsPrivate())
	}
}

func TestKeyCommandAliasesCompose(t *testing.T) {
	t.Parallel()
	tests := []struct {
		command *cobra.Command
		want    []string
	}{
		{command: keyCommand(t), want: []string{"k"}},
		{command: keyLeaf(t, "generate"), want: []string{"gen", "g"}},
		{command: keyLeaf(t, "public"), want: []string{"pub", "p"}},
		{command: keyLeaf(t, "inspect"), want: []string{"ins", "i"}},
		{command: keyLeaf(t, "convert"), want: []string{"conv", "c"}},
	}
	for _, test := range tests {
		if !slices.Equal(test.command.Aliases, test.want) {
			t.Fatalf("%s aliases = %q, want %q", test.command.CommandPath(), test.command.Aliases, test.want)
		}
	}

	privatePEM, _, err := executeRootStreams(t, "k", "g", "ed25519")
	require.NoError(t, err)
	privatePath := filepath.Join(t.TempDir(), "private.pem")
	require.NoError(t, os.WriteFile(privatePath, []byte(privatePEM), 0o600))

	publicPEM, _, err := executeRootStreams(t, "k", "p", "--input", privatePath)
	require.NoError(t, err)
	if block, _ := pem.Decode([]byte(publicPEM)); block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("public alias output = %q, want PKIX PEM", publicPEM)
	}
	publicPath := filepath.Join(t.TempDir(), "public.pem")
	require.NoError(t, os.WriteFile(publicPath, []byte(publicPEM), 0o600))

	inspected, _, err := executeRootStreams(t, "k", "i", "--input", privatePath, "--format", "json")
	require.NoError(t, err)
	if info := decodeKeyInfo(t, inspected); info.Algorithm != "ed25519" || info.KeyType != asym.KeyTypePrivate {
		t.Fatalf("inspect alias output = %+v", info)
	}

	openSSH, _, err := executeRootStreams(t, "k", "c", "--input", publicPath, "--to", "openssh")
	require.NoError(t, err)
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(openSSH)); err != nil {
		t.Fatal(err)
	}
}

func TestKeyGenerateRemovesBits(t *testing.T) {
	t.Parallel()
	if _, _, err := executeRootStreams(t, "key", "generate", "ed25519", "--bits", "256"); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("canonical --bits error = %v, want unknown flag", err)
	}
}

func TestKeyLifecycleComposesAcrossCommands(t *testing.T) {
	t.Parallel()
	privatePEM, _, err := executeRootStreams(t, "key", "generate", "ed25519")
	require.NoError(t, err)
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "private.pem")
	require.NoError(t, os.WriteFile(privatePath, []byte(privatePEM), 0o600))

	publicPEM, _, err := executeRootStreams(t, "key", "public", "--input", privatePath)
	require.NoError(t, err)
	block, rest := pem.Decode([]byte(publicPEM))
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("public output is not canonical PKIX PEM: %q", publicPEM)
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(directory, "public.pem")
	require.NoError(t, os.WriteFile(publicPath, []byte(publicPEM), 0o600))

	privateJSON, _, err := executeRootStreams(t, "key", "inspect", "--input", privatePath, "--format", "json")
	require.NoError(t, err)
	publicJSON, _, err := executeRootStreams(t, "key", "inspect", "--input", publicPath, "--format", "json")
	require.NoError(t, err)
	privateInfo := decodeKeyInfo(t, privateJSON)
	publicInfo := decodeKeyInfo(t, publicJSON)
	if privateInfo.KeyType != asym.KeyTypePrivate || publicInfo.KeyType != asym.KeyTypePublic {
		t.Fatalf("key types = %q, %q", privateInfo.KeyType, publicInfo.KeyType)
	}
	if privateInfo.PublicKeySHA256Fingerprint != publicInfo.PublicKeySHA256Fingerprint {
		t.Fatal("private and public fingerprints differ")
	}
	if strings.Contains(privateJSON, "PRIVATE KEY") || strings.Contains(privateJSON, privatePEM) {
		t.Fatalf("inspect output leaked private key: %q", privateJSON)
	}

	openSSH, _, err := executeRootStreams(t, "key", "public", "--input", privatePath, "--to", "openssh")
	require.NoError(t, err)
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(openSSH)); err != nil {
		t.Fatal(err)
	}
}

func TestKeyConsumersHonorEncodingAxes(t *testing.T) {
	t.Parallel()
	privatePEM, _, err := executeRootStreams(t, "key", "generate", "p256")
	require.NoError(t, err)
	directory := t.TempDir()
	encodedPath := filepath.Join(directory, "private.base64")
	encodedPrivate := base64.StdEncoding.EncodeToString([]byte(privatePEM))
	require.NoError(t, os.WriteFile(encodedPath, []byte(encodedPrivate), 0o600))

	encodedPublic, _, err := executeRootStreams(
		t,
		"key", "public", "--input", encodedPath, "--input-encoding", "base64", "--encoding", "base64",
	)
	require.NoError(t, err)
	publicPEM, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedPublic))
	require.NoError(t, err)
	publicBlock, _ := pem.Decode(publicPEM)
	if publicBlock == nil || publicBlock.Type != "PUBLIC KEY" {
		t.Fatalf("decoded public output = %q", publicPEM)
	}

	encodedDER, _, err := executeRootStreams(
		t,
		"key", "public", "--input", encodedPath, "--input-encoding", "base64", "--to", "pkix-der", "--encoding", "base64",
	)
	require.NoError(t, err)
	publicDER, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedDER))
	require.NoError(t, err)
	if _, err := x509.ParsePKIXPublicKey(publicDER); err != nil {
		t.Fatal(err)
	}

	inspected, _, err := executeRootStreams(
		t,
		"key", "inspect", "--input", encodedPath, "--input-encoding", "base64", "--format", "json",
	)
	require.NoError(t, err)
	if info := decodeKeyInfo(t, inspected); info.Algorithm != "ecdsa" || info.Curve != "P-256" {
		t.Fatalf("inspected encoded key = %+v", info)
	}
}

func TestKeyRegistriesDriveFlagsErrorsAndCompletion(t *testing.T) {
	t.Parallel()
	if !strings.Contains(keyLeaf(t, "generate").Long, "p256: ECDSA key on NIST P-256 (long: ecdsa-p256)") {
		t.Fatalf("key generate help = %q, want descriptive P-256 entry", keyLeaf(t, "generate").Long)
	}
	assertPositionalCompletionContains(t, keyLeaf(t, "generate"), "ed25519")
	assertPositionalCompletionContains(t, keyLeaf(t, "generate"), "ecdsa-p256")
	assertFlagCompletionContains(t, keyLeaf(t, "generate"), "public-format", "openssh")
	assertFlagCompletionContains(t, keyLeaf(t, "public"), "to", "openssh")
	assertFlagCompletionContains(t, keyLeaf(t, "convert"), "to", "openssh")
	assertFlagCompletionContains(t, keyLeaf(t, "inspect"), "format", "json")
	assertFlagCompletionContains(t, keyLeaf(t, "inspect"), "input-encoding", "base64")

	_, _, err := executeRootStreams(t, "key", "generate", "missing")
	if !errors.Is(err, errUnknownKeyAlgorithm) || !strings.Contains(err.Error(), "rsa4096") {
		t.Fatalf("algorithm error = %v", err)
	}
	_, _, err = executeRootStreams(t, "key", "convert", "--to", "missing")
	if !errors.Is(err, errUnknownKeyConversionTarget) || !strings.Contains(err.Error(), "openssh") {
		t.Fatalf("target error = %v", err)
	}
	if got, want := keycommand.PublicFormatNamesForTest(), []string{"openssh", "pkix-der", "pkix-pem"}; !slices.Equal(got, want) {
		t.Fatalf("public formats = %v, want %v", got, want)
	}
	_, _, err = executeRootStreams(t, "key", "inspect", "--format", "missing")
	if !errors.Is(err, errUnknownKeyFormat) || !strings.Contains(err.Error(), "json") {
		t.Fatalf("format error = %v", err)
	}
}

func TestKeyEnumValidationPrecedesOutputOpen(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"key", "generate", "missing"},
		{"key", "convert", "--to", "missing"},
	} {
		path := filepath.Join(t.TempDir(), "existing")
		require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
		args = append(args, "--output", path)
		if _, _, err := executeRootStreams(t, args...); err == nil {
			t.Fatalf("execute %v succeeded", args)
		}
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "preserve", string(data), "execute %v replaced output with %q", args, data)
	}
}

func TestKeyGenerateOutputUsesPrivatePermissions(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "private.pem")
	if _, _, err := executeRootStreams(t, "key", "generate", "ed25519", "--output", path); err != nil {
		t.Fatal(err)
	}
	testcmd.AssertPrivateOutput(t, path)
}

func TestKeyCommandsRejectCertificateInput(t *testing.T) {
	t.Parallel()
	certificate := testcmd.NewTLSCertificateChain(t).Certificate[0]
	path := filepath.Join(t.TempDir(), "certificate.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	require.NoError(t, os.WriteFile(path, data, 0o600))
	for _, args := range [][]string{
		{"key", "public", "--input", path},
		{"key", "inspect", "--input", path},
		{"key", "convert", "--input", path, "--to", "pkix-pem"},
	} {
		if _, _, err := executeRootStreams(t, args...); !errors.Is(err, asym.ErrUnexpectedKeyPEMType) {
			t.Fatalf("execute %v error = %v", args, err)
		}
	}
}

func decodeKeyInfo(t *testing.T, data string) asym.KeyInfo {
	t.Helper()
	var info asym.KeyInfo
	require.NoError(t, json.Unmarshal([]byte(data), &info))
	return info
}

func assertFlagCompletionContains(t *testing.T, command *cobra.Command, name, want string) {
	t.Helper()
	completion, ok := command.GetFlagCompletionFunc(name)
	if !ok {
		t.Fatalf("%s %s has no completion", command.CommandPath(), name)
	}
	values, directive := completion(command, nil, "")
	if !completionContains(values, want) {
		t.Fatalf("%s %s completions = %v, want %q", command.CommandPath(), name, values, want)
	}
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("%s %s directive = %v", command.CommandPath(), name, directive)
	}
}

func assertPositionalCompletionContains(t *testing.T, command *cobra.Command, want string) {
	t.Helper()
	values, directive := command.ValidArgsFunction(command, nil, "")
	if !completionContains(values, want) {
		t.Fatalf("%s completions = %v, want %q", command.CommandPath(), values, want)
	}
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("%s directive = %v", command.CommandPath(), directive)
	}
}

func completionContains(values []string, want string) bool {
	return slices.ContainsFunc(values, func(value string) bool {
		name, _, _ := strings.Cut(value, "\t")
		return name == want
	})
}

type keyFailingReader struct {
	err error
}

func (reader keyFailingReader) Read([]byte) (int, error) {
	return 0, reader.err
}
