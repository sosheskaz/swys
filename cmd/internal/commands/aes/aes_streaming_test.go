package aes_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
)

func TestAESStreamingFlagSurface(t *testing.T) {
	t.Parallel()

	encrypt := newAESLeaf(t, "encrypt")
	chunkSize := encrypt.Flags().Lookup("chunk-size")
	require.NotNil(t, chunkSize)
	if chunkSize.DefValue != "1M" || chunkSize.Shorthand != "" || chunkSize.NoOptDefVal != "" {
		t.Fatalf(
			"--chunk-size default/shorthand/no-option = %q/%q/%q, want 1M and explicit long value",
			chunkSize.DefValue,
			chunkSize.Shorthand,
			chunkSize.NoOptDefVal,
		)
	}
	for _, command := range []*cobra.Command{encrypt, newAESLeaf(t, "decrypt")} {
		raw := command.Flags().Lookup("raw")
		require.NotNil(t, raw, "%s has no --raw flag", command.CommandPath())
		if raw.DefValue != "false" || raw.Shorthand != "" {
			t.Fatalf("%s --raw default/shorthand = %q/%q, want false and none", command.CommandPath(), raw.DefValue, raw.Shorthand)
		}
	}
	if newAESLeaf(t, "decrypt").Flags().Lookup("chunk-size") != nil {
		t.Fatal("aes decrypt unexpectedly exposes --chunk-size")
	}
}

func TestAESChunkSizeSyntaxAndHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value string
		want  uint32
	}{
		{value: "64", want: 64},
		{value: "0.0625K", want: 64},
		{value: "1.5KB", want: 1500},
		{value: "1001", want: 1001},
		{value: "2kib", want: 2048},
		{value: "64MiB", want: 64 * 1024 * 1024},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			t.Parallel()
			wire, err := executeRoot(t, "aes", "encrypt", "payload", "--key", testAESKeyBase64, "--chunk-size", test.value)
			require.NoError(t, err)
			if len(wire) < testAESStreamHeaderSize {
				t.Fatalf("wire length = %d, want at least %d", len(wire), testAESStreamHeaderSize)
			}
			if got := binary.BigEndian.Uint32([]byte(wire)[12:16]); got != test.want {
				t.Fatalf("header chunk size = %d, want %d", got, test.want)
			}
		})
	}
}

func TestAESChunkSizeAndRawValidationPreservesOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{name: "below minimum", args: []string{"aes", "encrypt", "payload", "--key", testAESKeyBase64, "--chunk-size", "63"}},
		{name: "above maximum", args: []string{"aes", "encrypt", "payload", "--key", testAESKeyBase64, "--chunk-size", "67108865"}},
		{name: "fractional byte", args: []string{"aes", "encrypt", "payload", "--key", testAESKeyBase64, "--chunk-size", "0.1K"}},
		{name: "signed", args: []string{"aes", "encrypt", "payload", "--key", testAESKeyBase64, "--chunk-size=-64"}},
		{name: "exponent", args: []string{"aes", "encrypt", "payload", "--key", testAESKeyBase64, "--chunk-size", "1e3"}},
		{name: "unknown unit", args: []string{"aes", "encrypt", "payload", "--key", testAESKeyBase64, "--chunk-size", "1TiB"}},
		{name: "overflow", args: []string{"aes", "encrypt", "payload", "--key", testAESKeyBase64, "--chunk-size", "999999999999999999999999999G"}},
		{name: "raw chunk", args: []string{"aes", "encrypt", "payload", "--key", testAESKeyBase64, "--raw", "--chunk-size", "1M"}},
		{name: "CBC chunk", args: []string{"aes", "encrypt", "payload", "--key", testAESKeyBase64, "--cipher-mode", "cbc", "--chunk-size", "1M"}},
		{name: "CBC raw", args: []string{"aes", "encrypt", "payload", "--key", testAESKeyBase64, "--cipher-mode", "cbc", "--raw"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			outputPath := filepath.Join(t.TempDir(), "preserved")
			require.NoError(t, os.WriteFile(outputPath, []byte(testPreservedOutput), 0o600))
			args := append(slices.Clone(test.args), "--output", outputPath)
			if _, err := executeRoot(t, args...); err == nil {
				t.Fatalf("execute %q succeeded", args)
			}
			output, err := os.ReadFile(outputPath)
			require.NoError(t, err)
			if string(output) != testPreservedOutput {
				t.Fatalf("validation failure output = %q, want preserved content", output)
			}
		})
	}
}

func TestAESRawMigrationIsExplicitAndByteCompatible(t *testing.T) {
	t.Parallel()

	key, err := base64.StdEncoding.DecodeString(testAESKeyBase64)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := bytes.Repeat([]byte{0x5a}, aead.NonceSize())
	plaintext := []byte("legacy raw GCM fixture")
	aad := []byte("migration context")
	rawWire := append(bytes.Clone(nonce), aead.Seal(nil, nonce, plaintext, aad)...)
	rawPath := writeTestFile(t, "raw-gcm", rawWire)

	stdout, _, err := executeRootStreams(t, "aes", "decrypt", "--key", testAESKeyBase64, "--aad", string(aad), "--input", rawPath)
	if err == nil || stdout != "" {
		t.Fatalf("default decrypt of raw fixture = stdout %q, error %v; want failure without plaintext", stdout, err)
	}
	opened, _, err := executeRootStreams(t, "aes", "decrypt", "--raw", "--key", testAESKeyBase64, "--aad", string(aad), "--input", rawPath)
	require.NoError(t, err)
	if !bytes.Equal([]byte(opened), plaintext) {
		t.Fatalf("raw plaintext = %q, want %q", opened, plaintext)
	}

	wire, _, err := executeRootStreams(t, "aes", "encrypt", string(plaintext), "--raw", "--key", testAESKeyBase64, "--aad", string(aad))
	require.NoError(t, err)
	if len(wire) < aead.NonceSize()+aead.Overhead() {
		t.Fatalf("raw wire length = %d, want at least %d", len(wire), aead.NonceSize()+aead.Overhead())
	}
	openedByStandardLibrary, err := aead.Open(nil, []byte(wire)[:aead.NonceSize()], []byte(wire)[aead.NonceSize():], aad)
	require.NoError(t, err)
	if !bytes.Equal(openedByStandardLibrary, plaintext) {
		t.Fatalf("stdlib raw plaintext = %q, want %q", openedByStandardLibrary, plaintext)
	}
}

func TestAESStreamingCLIUsesExactAADBytes(t *testing.T) {
	t.Parallel()

	aad := []byte{0, 0xff, 'N', 'P', 'C', 0}
	plaintext := []byte("exact streaming AAD bytes")
	wire, _, err := executeRootStreams(
		t,
		"aes", "encrypt", string(plaintext),
		"--key", testAESKeyBase64,
		"--aad", string(aad),
		"--chunk-size", "97",
	)
	require.NoError(t, err)
	key, err := base64.StdEncoding.DecodeString(testAESKeyBase64)
	require.NoError(t, err)
	primitive, err := subtle.NewAESGCMHKDF(key, "SHA256", len(key), 97+16, 0)
	require.NoError(t, err)
	header := []byte(wire)[:testAESStreamHeaderSize]
	expectedAAD := make([]byte, 0, len("npc/aes-gcm-stream/v1\x00")+len(header)+len(aad))
	expectedAAD = append(expectedAAD, []byte("npc/aes-gcm-stream/v1\x00")...)
	expectedAAD = append(expectedAAD, header...)
	expectedAAD = append(expectedAAD, aad...)
	reader, err := primitive.NewDecryptingReader(
		strings.NewReader(wire[testAESStreamHeaderSize:]),
		expectedAAD,
	)
	require.NoError(t, err)
	opened, err := io.ReadAll(reader)
	require.NoError(t, err)
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("direct Tink plaintext = %q, want %q", opened, plaintext)
	}

	wirePath := writeTestFile(t, "stream-aad", []byte(wire))
	stdout, _, err := executeRootStreams(
		t,
		"aes", "decrypt", "--key", testAESKeyBase64,
		"--aad", string(append(bytes.Clone(aad), 0)),
		"--input", wirePath,
	)
	if err == nil || stdout != "" {
		t.Fatalf("wrong exact AAD = stdout %q, error %v; want no plaintext and failure", stdout, err)
	}
}

func TestAES192IsRejectedAcrossCLI(t *testing.T) {
	t.Parallel()

	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x19}, 24))
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "stream", args: []string{"aes", "encrypt", "payload", "--key", key}},
		{name: "raw", args: []string{"aes", "encrypt", "payload", "--raw", "--key", key}},
		{name: "CBC", args: []string{"aes", "encrypt", "payload", "--cipher-mode", "cbc", "--key", key}},
		{name: "unsupported key size", args: []string{"aes", "keygen", "--bits", "192"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			stdout, _, err := executeRootStreams(t, test.args...)
			if err == nil || stdout != "" {
				t.Fatalf("execute %q = stdout %q, error %v; want rejection without output", test.args, stdout, err)
			}
		})
	}

	completion := completeRoot(t, "aes", "keygen", "--bits", "")
	if strings.Contains(completion, "aes192") || strings.Contains(completion, "aes-192") {
		t.Fatalf("key completion retains AES-192: %q", completion)
	}
	help, err := executeRoot(t, "aes", "keygen", "--help")
	require.NoError(t, err)
	if strings.Contains(help, "AES-192") || strings.Contains(help, "aes192") || strings.Contains(help, "aes-192") {
		t.Fatalf("key generation help retains AES-192:\n%s", help)
	}
}

func TestAESStreamingCLIRetainsOnlyVerifiedPrefix(t *testing.T) {
	t.Parallel()

	const chunkSize = 64
	firstPlaintext := chunkSize - 24
	plaintext := make([]byte, firstPlaintext+chunkSize+20)
	for i := range plaintext {
		plaintext[i] = byte(i*31 + 7)
	}
	wire, _, err := executeRootStreams(
		t,
		"aes", "encrypt", string(plaintext),
		"--key", testAESKeyBase64,
		"--chunk-size", "64",
	)
	require.NoError(t, err)
	const finalSegmentStart = testAESStreamHeaderSize + 24 + 56 + 80
	corrupted := []byte(wire)
	corrupted[finalSegmentStart] ^= 1
	corruptedPath := writeTestFile(t, "corrupted-stream", corrupted)
	wantPrefix := plaintext[:firstPlaintext+chunkSize]

	stdout, _, err := executeRootStreams(
		t,
		"aes", "decrypt", "--key", testAESKeyBase64, "--input", corruptedPath,
	)
	if err == nil {
		t.Fatal("corrupted stream decrypted successfully to stdout")
	}
	if !bytes.Equal([]byte(stdout), wantPrefix) {
		t.Fatalf("stdout prefix = %d bytes, want exact %d-byte verified prefix", len(stdout), len(wantPrefix))
	}

	outputPath := filepath.Join(t.TempDir(), "opened")
	require.NoError(t, os.WriteFile(outputPath, []byte(testPreservedOutput), 0o600))
	_, _, err = executeRootStreams(
		t,
		"aes", "decrypt", "--key", testAESKeyBase64,
		"--input", corruptedPath, "--output", outputPath,
	)
	if err == nil {
		t.Fatal("corrupted stream decrypted successfully to a file")
	}
	opened, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	if !bytes.Equal(opened, wantPrefix) {
		t.Fatalf("file prefix = %d bytes, want exact %d-byte verified prefix", len(opened), len(wantPrefix))
	}
}

func TestAESDefaultDecryptDiagnosticsGuideExplicitMigration(t *testing.T) {
	t.Parallel()

	key, err := base64.StdEncoding.DecodeString(testAESKeyBase64)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := bytes.Repeat([]byte{0x6d}, aead.NonceSize())
	legacyRaw := append(bytes.Clone(nonce), aead.Seal(nil, nonce, []byte("legacy"), nil)...)
	for _, test := range []struct {
		name string
		wire []byte
	}{
		{name: "legacy raw ciphertext", wire: legacyRaw},
		{name: "other invalid magic", wire: append([]byte("NOT-NPC!"), bytes.Repeat([]byte{0x42}, 64)...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := writeTestFile(t, "ciphertext", test.wire)
			stdout, _, err := executeRootStreams(
				t,
				"aes", "decrypt", "--key", testAESKeyBase64, "--input", path,
			)
			if err == nil || stdout != "" {
				t.Fatalf("default decrypt = stdout %q, error %v; want failure without plaintext", stdout, err)
			}
			if !strings.Contains(err.Error(), "--raw") {
				t.Fatalf("default decrypt error = %q, want explicit --raw migration hint", err)
			}
			if strings.Contains(strings.ToLower(err.Error()), "detected") {
				t.Fatalf("default decrypt error claims format detection: %q", err)
			}
		})
	}
}

func TestAESDefaultDecryptDistinguishesKeySuiteMismatch(t *testing.T) {
	t.Parallel()

	aes256Key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, 32))
	wire, _, err := executeRootStreams(t, "aes", "encrypt", "payload", "--key", aes256Key)
	require.NoError(t, err)
	path := writeTestFile(t, "aes256-stream", []byte(wire))
	stdout, _, err := executeRootStreams(
		t,
		"aes", "decrypt", "--key", testAESKeyBase64, "--input", path,
	)
	if err == nil || stdout != "" {
		t.Fatalf("suite mismatch = stdout %q, error %v; want failure without plaintext", stdout, err)
	}
	diagnostic := strings.ToLower(err.Error())
	if !strings.Contains(diagnostic, "suite") || !strings.Contains(diagnostic, "key") {
		t.Fatalf("suite mismatch error = %q, want distinct key/suite diagnostic", err)
	}
}

func TestAESInvalidKeyLengthsPreserveOutputBeforeIO(t *testing.T) {
	t.Parallel()

	commands := []struct {
		name string
		args []string
	}{
		{name: "stream encrypt", args: []string{"aes", "encrypt", "payload"}},
		{name: "stream decrypt", args: []string{"aes", "decrypt", "ciphertext"}},
		{name: "raw encrypt", args: []string{"aes", "encrypt", "payload", "--raw"}},
		{name: "raw decrypt", args: []string{"aes", "decrypt", "ciphertext", "--raw"}},
		{name: "CBC encrypt", args: []string{"aes", "encrypt", "payload", "--cipher-mode", "cbc"}},
		{name: "CBC decrypt", args: []string{"aes", "decrypt", "ciphertext", "--cipher-mode", "cbc"}},
	}
	for _, command := range commands {
		for _, source := range []string{"flag", "file"} {
			t.Run(command.name+"/"+source+"/24", func(t *testing.T) {
				t.Parallel()
				assertAESInvalidKeyPreservesOutput(t, command.args, source, 24)
			})
		}
	}
	for _, keySize := range []int{0, 15, 33} {
		t.Run("other invalid length/flag/"+strconv.Itoa(keySize), func(t *testing.T) {
			t.Parallel()
			assertAESInvalidKeyPreservesOutput(t, []string{"aes", "encrypt", "payload"}, "flag", keySize)
		})
	}
}

func assertAESInvalidKeyPreservesOutput(t *testing.T, commandArgs []string, source string, keySize int) {
	t.Helper()
	directory := t.TempDir()
	outputPath := filepath.Join(directory, "output")
	require.NoError(t, os.WriteFile(outputPath, []byte(testPreservedOutput), 0o600))
	args := slices.Clone(commandArgs)
	key := bytes.Repeat([]byte{byte(keySize)}, keySize)
	if source == "flag" {
		args = append(args, "--key", base64.StdEncoding.EncodeToString(key))
	} else {
		keyPath := filepath.Join(directory, "key")
		require.NoError(t, os.WriteFile(keyPath, key, 0o600))
		args = append(args, "--keyfile", keyPath)
	}
	args = append(args, "--output", outputPath)
	stdout, _, err := executeRootStreams(t, args...)
	if err == nil || stdout != "" {
		t.Fatalf("invalid %d-byte key = stdout %q, error %v; want rejection", keySize, stdout, err)
	}
	output, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	if string(output) != testPreservedOutput {
		t.Fatalf("invalid %d-byte key changed output to %q", keySize, output)
	}
}
