package cmd_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/proto/aes_gcm_hkdf_streaming_go_proto"
	"github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	"github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	rootcmd "github.com/sosheskaz-systems/npc/cmd"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/artifact"
	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
)

func TestAESKeyContainerGenerationParameters(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		format   string
		bits     string
		args     []string
		keyBytes int
		derived  uint32
		segment  uint32
		hash     common_go_proto.HashType
	}{
		{name: "JSON defaults", format: "tink-json", keyBytes: 32, derived: 32, segment: 1 << 20, hash: common_go_proto.HashType_SHA256},
		{name: "binary defaults", format: "tink-binary", keyBytes: 32, derived: 32, segment: 1 << 20, hash: common_go_proto.HashType_SHA256},
		{name: "AES128", format: "tink-json", bits: "128", keyBytes: 16, derived: 16, segment: 1 << 20, hash: common_go_proto.HashType_SHA256},
		{
			name: "custom Tink parameters", format: "tink-json", bits: "256",
			args:     []string{"--chunk-size", "64", "--hkdf-hash", "sha512", "--derived-key-bits", "128"},
			keyBytes: 32, derived: 16, segment: 64, hash: common_go_proto.HashType_SHA512,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "keyset")
			args := []string{"aes", "keygen", "--key-format", tc.format, "--output", path}
			if tc.bits != "" {
				args = append(args, "--bits", tc.bits)
			}
			args = append(args, tc.args...)
			_, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, args...)
			require.NoError(t, err)
			ks := nativeAESKeysetMaterial(t, path, tc.format)
			require.Len(t, ks.Key, 1)
			require.NotZero(t, ks.PrimaryKeyId)
			require.Equal(t, ks.PrimaryKeyId, ks.Key[0].KeyId)
			require.Equal(t, tink_go_proto.KeyStatusType_ENABLED, ks.Key[0].Status)
			require.Equal(t, aesGCMHKDFTypeURL, ks.Key[0].KeyData.TypeUrl)
			key := new(aes_gcm_hkdf_streaming_go_proto.AesGcmHkdfStreamingKey)
			require.NoError(t, proto.Unmarshal(ks.Key[0].KeyData.Value, key))
			require.Len(t, key.KeyValue, tc.keyBytes)
			require.Equal(t, tc.derived, key.Params.DerivedKeySize)
			require.Equal(t, tc.segment, key.Params.CiphertextSegmentSize)
			require.Equal(t, tc.hash, key.Params.HkdfHashType)
		})
	}
}

func TestAESKeyContainerPreservesMultipleKeysAndRequiresSelectionForRawExport(t *testing.T) {
	t.Parallel()
	first := bytes.Repeat([]byte{0x41}, 32)
	second := bytes.Repeat([]byte{0x42}, 16)
	ks := &tink_go_proto.Keyset{
		PrimaryKeyId: 101,
		Key: []*tink_go_proto.Keyset_Key{
			fixtureAESKey(t, 101, first, tink_go_proto.KeyStatusType_ENABLED),
			fixtureAESKey(t, 202, second, tink_go_proto.KeyStatusType_DISABLED),
		},
	}
	require.NoError(t, keyset.Validate(ks), "test fixture must be a structurally valid Tink keyset")
	fixtureHandle, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(bytes.NewReader(jsonAESFixture(t, ks))))
	require.NoError(t, err)
	_, err = streamingaead.New(fixtureHandle)
	require.NoError(t, err, "test fixture must instantiate Tink's native streaming primitive")
	input := writeAESKeysetFixture(t, ks, "tink-json")
	binaryPath := filepath.Join(t.TempDir(), "converted.bin")
	_, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-convert", "--from", "tink-json", "--to", "tink-binary", "--input", input, "--output", binaryPath)
	require.NoError(t, err)
	got := nativeAESKeysetMaterial(t, binaryPath, "tink-binary")
	require.True(t, proto.Equal(ks, got), "container conversion must preserve all IDs, status, primary and key parameters")

	for _, tc := range []struct {
		name  string
		flags []string
		want  []byte
		fail  bool
	}{
		{name: "ambiguous without ID", fail: true},
		{name: "enabled explicit ID", flags: []string{"--key-id", "101"}, want: first},
		{name: "disabled explicit ID", flags: []string{"--key-id", "202"}, fail: true},
		{name: "unknown explicit ID", flags: []string{"--key-id", "303"}, fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			output := filepath.Join(t.TempDir(), "raw.key")
			require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))
			args := []string{"aes", "key-convert", "--from", "tink-binary", "--to", "raw", "--input", binaryPath, "--output", output}
			args = append(args, tc.flags...)
			_, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, args...)
			if tc.fail {
				require.Error(t, err)
				contents, readErr := os.ReadFile(output)
				require.NoError(t, readErr)
				require.Equal(t, []byte("preserve"), contents)
				return
			}
			require.NoError(t, err)
			contents, readErr := os.ReadFile(output)
			require.NoError(t, readErr)
			require.Equal(t, tc.want, contents)
		})
	}
}

func TestAESKeyContainerImportsRawMaterialIntoNativeKeyset(t *testing.T) {
	t.Parallel()
	material := bytes.Repeat([]byte{0x5a}, 16)
	input := filepath.Join(t.TempDir(), "raw.key")
	output := filepath.Join(t.TempDir(), "keyset.json")
	require.NoError(t, os.WriteFile(input, material, 0o600))
	_, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-convert", "--from", "raw", "--to", "tink-json", "--input", input,
		"--output", output, "--chunk-size", "64", "--hkdf-hash", "sha512", "--derived-key-bits", "128")
	require.NoError(t, err)
	handle := readNativeAESKeyset(t, output, "tink-json")
	_, err = streamingaead.New(handle)
	require.NoError(t, err)
	ks := insecurecleartextkeyset.KeysetMaterial(handle)
	require.Len(t, ks.Key, 1)
	require.NotZero(t, ks.PrimaryKeyId)
	require.Equal(t, ks.PrimaryKeyId, ks.Key[0].KeyId)
	require.Equal(t, tink_go_proto.KeyStatusType_ENABLED, ks.Key[0].Status)
	key := new(aes_gcm_hkdf_streaming_go_proto.AesGcmHkdfStreamingKey)
	require.NoError(t, proto.Unmarshal(ks.Key[0].KeyData.Value, key))
	require.Equal(t, material, key.KeyValue)
	require.Equal(t, uint32(64), key.Params.CiphertextSegmentSize)
	require.Equal(t, uint32(16), key.Params.DerivedKeySize)
	require.Equal(t, common_go_proto.HashType_SHA512, key.Params.HkdfHashType)
}

func TestAESKeyContainerConversionUsesByteEncodingHooks(t *testing.T) {
	t.Parallel()
	material := bytes.Repeat([]byte{0x6b}, 32)
	input := filepath.Join(t.TempDir(), "raw.b64")
	require.NoError(t, os.WriteFile(input, []byte(base64.StdEncoding.EncodeToString(material)), 0o600))
	encoded, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-convert", "--from", "raw", "--to", "tink-binary",
		"--input", input, "--input-encoding", "base64", "--encoding", "base64")
	require.NoError(t, err)
	container, err := base64.StdEncoding.DecodeString(string(encoded))
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "keyset.bin")
	require.NoError(t, os.WriteFile(path, container, 0o600))
	ks := nativeAESKeysetMaterial(t, path, "tink-binary")
	require.Len(t, ks.Key, 1)
	key := new(aes_gcm_hkdf_streaming_go_proto.AesGcmHkdfStreamingKey)
	require.NoError(t, proto.Unmarshal(ks.Key[0].KeyData.Value, key))
	require.Equal(t, material, key.KeyValue)
}

func TestAESKeyContainerRejectsInvalidInputsBeforeOutput(t *testing.T) {
	t.Parallel()
	valid := &tink_go_proto.Keyset{
		PrimaryKeyId: 101,
		Key: []*tink_go_proto.Keyset_Key{
			fixtureAESKey(t, 101, bytes.Repeat([]byte{0x42}, 32), tink_go_proto.KeyStatusType_ENABLED),
		},
	}
	badPrimitive := cloneAESFixtureKeyset(t, valid)
	badPrimitive.Key[0].KeyData.TypeUrl = "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey"
	badHash := cloneAESFixtureKeyset(t, valid)
	changeAESFixtureKey(t, badHash.Key[0], func(key *aes_gcm_hkdf_streaming_go_proto.AesGcmHkdfStreamingKey) {
		key.Params.HkdfHashType = common_go_proto.HashType_SHA1
	})
	badSegment := cloneAESFixtureKeyset(t, valid)
	changeAESFixtureKey(t, badSegment.Key[0], func(key *aes_gcm_hkdf_streaming_go_proto.AesGcmHkdfStreamingKey) {
		key.Params.CiphertextSegmentSize = 64<<20 + 1
	})
	badKeySize := cloneAESFixtureKeyset(t, valid)
	changeAESFixtureKey(t, badKeySize.Key[0], func(key *aes_gcm_hkdf_streaming_go_proto.AesGcmHkdfStreamingKey) {
		key.KeyValue = bytes.Repeat([]byte{0x42}, 24)
	})

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "malformed JSON", data: []byte("{")},
		{name: "unrecognized primitive", data: jsonAESFixture(t, badPrimitive)},
		{name: "unsupported hash", data: jsonAESFixture(t, badHash)},
		{name: "oversized segment", data: jsonAESFixture(t, badSegment)},
		{name: "AES192 key", data: jsonAESFixture(t, badKeySize)},
		{name: "oversized artifact", data: bytes.Repeat([]byte{'x'}, int(artifact.MaxKeyBytes)+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := filepath.Join(t.TempDir(), "input.json")
			output := filepath.Join(t.TempDir(), "output.bin")
			require.NoError(t, os.WriteFile(input, tc.data, 0o600))
			require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))
			_, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
				"aes", "key-convert", "--from", "tink-json", "--to", "tink-binary", "--input", input, "--output", output)
			require.Error(t, err)
			contents, readErr := os.ReadFile(output)
			require.NoError(t, readErr)
			require.Equal(t, []byte("preserve"), contents)
		})
	}
}

func TestAESKeyContainerRejectsInvalidGenerationFlagsBeforeOutput(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "raw rejects Tink hash", args: []string{"--key-format", "raw", "--hkdf-hash", "sha256"}},
		{name: "raw rejects Tink segment", args: []string{"--chunk-size", "1MiB"}},
		{name: "derived key exceeds input", args: []string{"--key-format", "tink-json", "--bits", "128", "--derived-key-bits", "256"}},
		{name: "segment below Tink minimum", args: []string{"--key-format", "tink-json", "--chunk-size", "63"}},
		{name: "segment above limit", args: []string{"--key-format", "tink-json", "--chunk-size", "67108865"}},
		{name: "unsupported hash", args: []string{"--key-format", "tink-json", "--hkdf-hash", "sha1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			output := filepath.Join(t.TempDir(), "preserved")
			require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))
			args := append([]string{"aes", "keygen", "--output", output}, tc.args...)
			_, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, args...)
			require.Error(t, err)
			contents, readErr := os.ReadFile(output)
			require.NoError(t, readErr)
			require.Equal(t, []byte("preserve"), contents)
		})
	}
}

func TestAESKeyInspectionOmitsSecretAndUsesNormalFormats(t *testing.T) {
	t.Parallel()
	material := bytes.Repeat([]byte("private!"), 4)
	ks := &tink_go_proto.Keyset{PrimaryKeyId: 101, Key: []*tink_go_proto.Keyset_Key{fixtureAESKey(t, 101, material, tink_go_proto.KeyStatusType_ENABLED)}}
	input := writeAESKeysetFixture(t, ks, "tink-json")
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			t.Parallel()
			output, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
				"aes", "key-inspect", "--key-format", "tink-json", "--input", input, "--format", format)
			require.NoError(t, err)
			require.NotContains(t, string(output), string(material))
			require.NotContains(t, string(output), base64.StdEncoding.EncodeToString(material))
			require.Contains(t, string(output), "101", "inspection should identify the primary key")
			if format == "json" {
				var decoded any
				require.NoError(t, json.Unmarshal(output, &decoded))
			}
		})
	}
	rawPath := filepath.Join(t.TempDir(), "raw.key")
	require.NoError(t, os.WriteFile(rawPath, material, 0o600))
	rawInspection, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-inspect", "--input", rawPath, "--format", "json")
	require.NoError(t, err, "raw is the default inspection container")
	var decoded any
	require.NoError(t, json.Unmarshal(rawInspection, &decoded))
	require.NotContains(t, string(rawInspection), string(material))
	require.NotContains(t, string(rawInspection), base64.StdEncoding.EncodeToString(material))
}

func TestAESKeyContainerProtectsSensitiveOutputAndInput(t *testing.T) {
	t.Parallel()
	input := filepath.Join(t.TempDir(), "raw.key")
	require.NoError(t, os.WriteFile(input, bytes.Repeat([]byte{0x42}, 32), 0o600))
	_, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-convert", "--from", "raw", "--to", "tink-json", "--input", input, "--output", input)
	require.Error(t, err)
	unchanged, readErr := os.ReadFile(input)
	require.NoError(t, readErr)
	require.Equal(t, bytes.Repeat([]byte{0x42}, 32), unchanged)

	if runtime.GOOS == "windows" {
		return
	}
	output := filepath.Join(t.TempDir(), "insecure.json")
	require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o644))
	_, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-convert", "--from", "raw", "--to", "tink-json", "--input", input, "--output", output)
	require.Error(t, err)
	unchanged, readErr = os.ReadFile(output)
	require.NoError(t, readErr)
	require.Equal(t, []byte("preserve"), unchanged)
}

func TestAESKeyContainerPreservesReadFailureAndDestination(t *testing.T) {
	t.Parallel()
	fixture := &tink_go_proto.Keyset{
		PrimaryKeyId: 101,
		Key: []*tink_go_proto.Keyset_Key{
			fixtureAESKey(t, 101, bytes.Repeat([]byte{0x42}, 32), tink_go_proto.KeyStatusType_ENABLED),
		},
	}
	input := io.MultiReader(bytes.NewReader(jsonAESFixture(t, fixture)), iotest.ErrReader(errAESKeysetInputFailed))
	output := filepath.Join(t.TempDir(), "converted.bin")
	require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))
	stdout, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), input,
		"aes", "key-convert", "--from", "tink-json", "--to", "tink-binary", "--output", output)
	require.ErrorIs(t, err, errAESKeysetInputFailed)
	require.Empty(t, stdout)
	contents, readErr := os.ReadFile(output)
	require.NoError(t, readErr)
	require.Equal(t, []byte("preserve"), contents)
}

const aesGCMHKDFTypeURL = "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey"

var errAESKeysetInputFailed = errors.New("keyset input failed")

func fixtureAESKey(t *testing.T, id uint32, material []byte, status tink_go_proto.KeyStatusType) *tink_go_proto.Keyset_Key {
	t.Helper()
	encoded, err := proto.Marshal(&aes_gcm_hkdf_streaming_go_proto.AesGcmHkdfStreamingKey{
		Params: &aes_gcm_hkdf_streaming_go_proto.AesGcmHkdfStreamingParams{
			CiphertextSegmentSize: 1 << 20, DerivedKeySize: uint32(len(material)), HkdfHashType: common_go_proto.HashType_SHA256,
		},
		KeyValue: material,
	})
	require.NoError(t, err)
	return &tink_go_proto.Keyset_Key{
		KeyId: id, Status: status, OutputPrefixType: tink_go_proto.OutputPrefixType_RAW,
		KeyData: &tink_go_proto.KeyData{
			TypeUrl: aesGCMHKDFTypeURL, Value: encoded, KeyMaterialType: tink_go_proto.KeyData_SYMMETRIC,
		},
	}
}

func changeAESFixtureKey(t *testing.T, entry *tink_go_proto.Keyset_Key, change func(*aes_gcm_hkdf_streaming_go_proto.AesGcmHkdfStreamingKey)) {
	t.Helper()
	key := new(aes_gcm_hkdf_streaming_go_proto.AesGcmHkdfStreamingKey)
	require.NoError(t, proto.Unmarshal(entry.KeyData.Value, key))
	change(key)
	encoded, err := proto.Marshal(key)
	require.NoError(t, err)
	entry.KeyData.Value = encoded
}

func cloneAESFixtureKeyset(t *testing.T, fixture *tink_go_proto.Keyset) *tink_go_proto.Keyset {
	t.Helper()
	cloned, ok := proto.Clone(fixture).(*tink_go_proto.Keyset)
	require.True(t, ok)
	return cloned
}

func jsonAESFixture(t *testing.T, ks *tink_go_proto.Keyset) []byte {
	t.Helper()
	data, err := protojson.Marshal(ks)
	require.NoError(t, err)
	return data
}

func writeAESKeysetFixture(t *testing.T, ks *tink_go_proto.Keyset, format string) string {
	t.Helper()
	var data []byte
	var err error
	switch format {
	case "tink-json":
		data = jsonAESFixture(t, ks)
	case "tink-binary":
		data, err = proto.Marshal(ks)
	default:
		t.Fatalf("unknown fixture format %q", format)
	}
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "keyset-"+format)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func nativeAESKeysetMaterial(t *testing.T, path, format string) *tink_go_proto.Keyset {
	t.Helper()
	return insecurecleartextkeyset.KeysetMaterial(readNativeAESKeyset(t, path, format))
}
