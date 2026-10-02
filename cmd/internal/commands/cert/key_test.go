package cert_test

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
	"github.com/sosheskaz-systems/npc/internal/asym"
)

var errKeyTestReadFailed = errors.New("read failed")

func TestCertKeyCommandsUseCanonicalNames(t *testing.T) {
	t.Parallel()
	tests := []struct {
		command *cobra.Command
		want    []string
	}{
		{command: keyLeaf(t, "public"), want: nil},
		{command: keyLeaf(t, "inspect"), want: nil},
		{command: keyLeaf(t, "convert"), want: nil},
	}
	for _, test := range tests {
		if !slices.Equal(test.command.Aliases, test.want) {
			t.Fatalf("%s aliases = %q, want %q", test.command.CommandPath(), test.command.Aliases, test.want)
		}
	}

	privatePEM, _, err := executeRootStreams(t, "cert", "keygen")
	require.NoError(t, err)
	privatePath := filepath.Join(t.TempDir(), "private.pem")
	require.NoError(t, os.WriteFile(privatePath, []byte(privatePEM), 0o600))

	publicPEM, _, err := executeRootStreams(t, "cert", "key-public", "--input", privatePath)
	require.NoError(t, err)
	if block, _ := pem.Decode([]byte(publicPEM)); block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("public alias output = %q, want PKIX PEM", publicPEM)
	}
	publicPath := filepath.Join(t.TempDir(), "public.pem")
	require.NoError(t, os.WriteFile(publicPath, []byte(publicPEM), 0o600))

	inspected, _, err := executeRootStreams(t, "cert", "key-inspect", "--input", privatePath, "--format", "json")
	require.NoError(t, err)
	if info := decodeKeyInfo(t, inspected); info.Algorithm != "ed25519" || info.KeyType != asym.KeyTypePrivate {
		t.Fatalf("inspect alias output = %+v", info)
	}

	openSSH, _, err := executeRootStreams(t, "cert", "key-convert", "--input", publicPath, "--to", "openssh")
	require.NoError(t, err)
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(openSSH)); err != nil {
		t.Fatal(err)
	}
}

func TestRemovedTopLevelKeyCommands(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"key"}, {"k"}, {"key", "public"}, {"key", "convert"}, {"key", "inspect"}} {
		_, _, err := executeRootStreams(t, args...)
		require.Error(t, err, "removed command %v", args)
	}
}

func TestKeyLifecycleComposesAcrossCommands(t *testing.T) {
	t.Parallel()
	privatePEM, _, err := executeRootStreams(t, "cert", "keygen")
	require.NoError(t, err)
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "private.pem")
	require.NoError(t, os.WriteFile(privatePath, []byte(privatePEM), 0o600))

	publicPEM, _, err := executeRootStreams(t, "cert", "key-public", "--input", privatePath)
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

	privateJSON, _, err := executeRootStreams(t, "cert", "key-inspect", "--input", privatePath, "--format", "json")
	require.NoError(t, err)
	publicJSON, _, err := executeRootStreams(t, "cert", "key-inspect", "--input", publicPath, "--format", "json")
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

	openSSH, _, err := executeRootStreams(t, "cert", "key-public", "--input", privatePath, "--to", "openssh")
	require.NoError(t, err)
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(openSSH)); err != nil {
		t.Fatal(err)
	}
}

func TestKeyConsumersHonorEncodingAxes(t *testing.T) {
	t.Parallel()
	privatePEM, _, err := executeRootStreams(t, "cert", "keygen", "--algorithm", "p256")
	require.NoError(t, err)
	directory := t.TempDir()
	encodedPath := filepath.Join(directory, "private.base64")
	encodedPrivate := base64.StdEncoding.EncodeToString([]byte(privatePEM))
	require.NoError(t, os.WriteFile(encodedPath, []byte(encodedPrivate), 0o600))

	encodedPublic, _, err := executeRootStreams(
		t,
		"cert", "key-public", "--input", encodedPath, "--input-encoding", "base64", "--encoding", "base64",
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
		"cert", "key-public", "--input", encodedPath, "--input-encoding", "base64", "--to", "pkix-der", "--encoding", "base64",
	)
	require.NoError(t, err)
	publicDER, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedDER))
	require.NoError(t, err)
	if _, err := x509.ParsePKIXPublicKey(publicDER); err != nil {
		t.Fatal(err)
	}

	inspected, _, err := executeRootStreams(
		t,
		"cert", "key-inspect", "--input", encodedPath, "--input-encoding", "base64", "--format", "json",
	)
	require.NoError(t, err)
	if info := decodeKeyInfo(t, inspected); info.Algorithm != "ecdsa" || info.Curve != "P-256" {
		t.Fatalf("inspected encoded key = %+v", info)
	}
}

func TestKeyRegistriesDriveFlagsErrorsAndCompletion(t *testing.T) {
	t.Parallel()
	assertFlagCompletionContains(t, keyLeaf(t, "public"), "to", "openssh")
	assertFlagCompletionContains(t, keyLeaf(t, "convert"), "to", "openssh")
	assertFlagCompletionContains(t, keyLeaf(t, "inspect"), "format", "json")
	assertFlagCompletionContains(t, keyLeaf(t, "inspect"), "input-encoding", "base64")

	_, _, err := executeRootStreams(t, "cert", "key-convert", "--to", "missing")
	require.ErrorIs(t, err, errUnknownKeyConversionTarget)
	_, _, err = executeRootStreams(t, "cert", "key-inspect", "--format", "missing")
	require.ErrorIs(t, err, errUnknownKeyFormat)
}

func TestKeyEnumValidationPrecedesOutputOpen(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"cert", "key-convert", "--to", "missing"},
		{"cert", "key-inspect", "--format", "missing"},
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

func TestKeyCommandsRejectCertificateInput(t *testing.T) {
	t.Parallel()
	certificate := testcmd.NewTLSCertificateChain(t).Certificate[0]
	path := filepath.Join(t.TempDir(), "certificate.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	require.NoError(t, os.WriteFile(path, data, 0o600))
	for _, args := range [][]string{
		{"cert", "key-public", "--input", path},
		{"cert", "key-inspect", "--input", path},
		{"cert", "key-convert", "--input", path, "--to", "pkix-pem"},
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

func TestKeyInspectionPreservesReadErrors(t *testing.T) {
	t.Parallel()
	_, _, err := executeRootStreamsWithInput(t, keyFailingReader{err: errKeyTestReadFailed}, "cert", "key-inspect")
	require.ErrorIs(t, err, errKeyTestReadFailed)
}

func TestKeyInspectionPreservesOutputOnMalformedInput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	input := filepath.Join(dir, "malformed.key")
	output := filepath.Join(dir, "report.json")
	require.NoError(t, os.WriteFile(input, []byte("not a key"), 0o600))
	require.NoError(t, os.WriteFile(output, []byte("sentinel"), 0o600))
	_, _, err := executeRootStreams(t, "cert", "key-inspect", "--input", input, "--format", "json", "--output", output)
	require.ErrorIs(t, err, asym.ErrMalformedKey)
	remaining, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.Equal(t, "sentinel", string(remaining))
}
