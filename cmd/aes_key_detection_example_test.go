package cmd_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"

	rootcmd "github.com/sosheskaz/swys/cmd"
	"github.com/sosheskaz/swys/cmd/internal/cli/artifact"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

func TestExampleAESKeyReadersDetectContainerFormats(t *testing.T) {
	t.Parallel()
	raw := bytes.Repeat([]byte{0x42}, 32)
	keyset := &tink_go_proto.Keyset{
		PrimaryKeyId: 101,
		Key: []*tink_go_proto.Keyset_Key{
			fixtureAESKey(t, 101, raw, tink_go_proto.KeyStatusType_ENABLED),
		},
	}
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "keyset.json")
	binaryPath := filepath.Join(dir, "keyset.bin")
	rawPath := filepath.Join(dir, "key.bin")
	require.NoError(t, os.WriteFile(jsonPath, append([]byte(" \n\t"), jsonAESFixture(t, keyset)...), 0o600))

	inspection, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-inspect", "--input", jsonPath, "--format", "json")
	require.NoError(t, err)
	var metadata struct {
		PrimaryKeyID uint32 `json:"primary_key_id"`
	}
	require.NoError(t, json.Unmarshal(inspection, &metadata))
	require.Equal(t, uint32(101), metadata.PrimaryKeyID)
	require.NotContains(t, string(inspection), string(raw))

	_, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-convert", "--to", "tink-binary", "--input", jsonPath, "--output", binaryPath)
	require.NoError(t, err)
	require.True(t, proto.Equal(keyset, nativeAESKeysetMaterial(t, binaryPath, "tink-binary")))

	inspection, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-inspect", "--key-format", "auto", "--input", binaryPath, "--format", "json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(inspection, &metadata))
	require.Equal(t, uint32(101), metadata.PrimaryKeyID)

	_, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-convert", "--from", "auto", "--to", "raw", "--input", binaryPath, "--output", rawPath)
	require.NoError(t, err)
	got, err := os.ReadFile(rawPath)
	require.NoError(t, err)
	require.Equal(t, raw, got)
}

func TestExampleAESKeyInspectionEncodesCompleteStdout(t *testing.T) {
	t.Parallel()
	input := filepath.Join(t.TempDir(), "raw.key")
	require.NoError(t, os.WriteFile(input, bytes.Repeat([]byte{0x42}, 16), 0o600))

	plain, stderr, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-inspect", "--input", input)
	require.NoError(t, err, "unencoded inspection: stderr %q", stderr)
	require.Equal(t, []byte("AES Key Metadata\n    Format  raw\n    Bits    128\n"), plain)

	encoded, stderr, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-inspect", "--input", input, "-e", "base64")
	require.NoError(t, err, "encoded inspection: stderr %q", stderr)
	require.Equal(t, base64.StdEncoding.EncodeToString(plain), string(encoded))
}

func TestAESAutoKeyReadersPreferRawLengthAndRespectExplicitFormat(t *testing.T) {
	t.Parallel()
	raw := append([]byte("{raw-key}"), bytes.Repeat([]byte{'x'}, 16-len("{raw-key}"))...)
	path := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(path, raw, 0o600))

	inspection, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-inspect", "--input", path)
	require.NoError(t, err)
	require.Contains(t, string(inspection), "AES Key Metadata\n    Format  raw\n    Bits    128")

	output := filepath.Join(t.TempDir(), "converted")
	_, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-convert", "--to", "raw", "--input", path, "--output", output)
	require.NoError(t, err)
	got, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, raw, got)

	_, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-inspect", "--key-format", "tink-json", "--input", path)
	require.Error(t, err)
	require.NotContains(t, err.Error(), string(raw))

	require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))
	_, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-convert", "--from", "tink-json", "--to", "raw", "--input", path, "--output", output)
	require.Error(t, err)
	require.NotContains(t, err.Error(), string(raw))
	got, err = os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, []byte("preserve"), got)
}

func TestAESKeyReadersAcceptExplicitAuto(t *testing.T) {
	t.Parallel()
	raw := bytes.Repeat([]byte{0x42}, 16)
	input := filepath.Join(t.TempDir(), "raw.key")
	require.NoError(t, os.WriteFile(input, raw, 0o600))
	inspection, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-inspect", "--key-format", "auto", "--input", input)
	require.NoError(t, err)
	require.Contains(t, string(inspection), "AES Key Metadata\n    Format  raw\n    Bits    128")

	output, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-convert", "--from", "auto", "--to", "raw", "--input", input)
	require.NoError(t, err)
	require.Equal(t, raw, output)
}

func TestAESAutoKeyReadersPrefer32ByteRawWithJSONPrefix(t *testing.T) {
	t.Parallel()
	raw := append([]byte("{raw-key}"), bytes.Repeat([]byte{'x'}, 32-len("{raw-key}"))...)
	input := filepath.Join(t.TempDir(), "raw.key")
	require.NoError(t, os.WriteFile(input, raw, 0o600))
	inspection, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-inspect", "--input", input)
	require.NoError(t, err)
	require.Contains(t, string(inspection), "AES Key Metadata\n    Format  raw\n    Bits    256")

	output, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-convert", "--to", "raw", "--input", input)
	require.NoError(t, err)
	require.Equal(t, raw, output)
}

func TestAESAutoKeyConversionAppliesDetectedSourceConstraintsBeforeOutput(t *testing.T) {
	t.Parallel()
	raw := bytes.Repeat([]byte{0x52}, 16)
	keyset := &tink_go_proto.Keyset{
		PrimaryKeyId: 101,
		Key: []*tink_go_proto.Keyset_Key{
			fixtureAESKey(t, 101, raw, tink_go_proto.KeyStatusType_ENABLED),
		},
	}
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "raw.key")
	jsonPath := filepath.Join(dir, "keyset.json")
	require.NoError(t, os.WriteFile(rawPath, raw, 0o600))
	require.NoError(t, os.WriteFile(jsonPath, jsonAESFixture(t, keyset), 0o600))

	for _, tc := range []struct {
		name  string
		input string
		to    string
		want  string
		flags []string
	}{
		{name: "container rejects import parameters", input: jsonPath, to: "tink-binary", flags: []string{"--chunk-size", "64"}, want: "--chunk-size"},
		{name: "raw rejects key ID", input: rawPath, to: "raw", flags: []string{"--key-id", "101"}, want: "--key-id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			output := filepath.Join(t.TempDir(), "output")
			require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))
			args := []string{"aes", "key-convert", "--to", tc.to, "--input", tc.input, "--output", output}
			args = append(args, tc.flags...)
			_, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, args...)
			require.Error(t, err)
			require.ErrorContains(t, err, tc.want)
			got, readErr := os.ReadFile(output)
			require.NoError(t, readErr)
			require.Equal(t, []byte("preserve"), got)
		})
	}

	output := filepath.Join(dir, "imported.bin")
	_, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-convert", "--to", "tink-binary", "--input", rawPath, "--output", output,
		"--chunk-size", "64", "--hkdf-hash", "sha512", "--derived-key-bits", "128")
	require.NoError(t, err)
	require.Len(t, nativeAESKeysetMaterial(t, output, "tink-binary").Key, 1)
}

func TestAESAutoKeyConversionBoundsContainerAndExplicitRawInputs(t *testing.T) {
	t.Parallel()
	keyset := &tink_go_proto.Keyset{
		PrimaryKeyId: 101,
		Key: []*tink_go_proto.Keyset_Key{
			fixtureAESKey(t, 101, bytes.Repeat([]byte{0x42}, 32), tink_go_proto.KeyStatusType_ENABLED),
		},
	}
	input := writeAESKeysetFixture(t, keyset)
	output := filepath.Join(t.TempDir(), "output")
	require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))
	_, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-convert", "--from", "raw", "--to", "tink-binary", "--input", input, "--output", output)
	require.ErrorIs(t, err, artifact.ErrTooLarge)
	got, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, []byte("preserve"), got)
}

func TestAESAutoKeyReadersRejectOversizedInputBeforeOutput(t *testing.T) {
	t.Parallel()
	input := filepath.Join(t.TempDir(), "oversized.key")
	require.NoError(t, os.WriteFile(input, bytes.Repeat([]byte{'x'}, int(artifact.MaxKeyBytes)+1), 0o600))
	for _, tc := range []struct {
		command string
		flags   []string
	}{
		{command: "key-inspect"},
		{command: "key-convert", flags: []string{"--to", "raw"}},
	} {
		t.Run(tc.command, func(t *testing.T) {
			t.Parallel()
			output := filepath.Join(t.TempDir(), "output")
			require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))
			args := append([]string{"aes", tc.command}, tc.flags...)
			args = append(args, "--input", input, "--output", output)
			_, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, args...)
			require.ErrorIs(t, err, artifact.ErrTooLarge)
			got, readErr := os.ReadFile(output)
			require.NoError(t, readErr)
			require.Equal(t, []byte("preserve"), got)
		})
	}
}

func TestAESAutoKeyConversionPreservesStdinAndEncoding(t *testing.T) {
	t.Parallel()
	raw := bytes.Repeat([]byte{0x6b}, 16)
	encoded := base64.StdEncoding.EncodeToString(raw)
	output, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewBufferString(encoded),
		"aes", "key-convert", "--to", "raw", "--input-encoding", "base64", "--encoding", "base64")
	require.NoError(t, err)
	got, err := base64.StdEncoding.DecodeString(string(output))
	require.NoError(t, err)
	require.Equal(t, raw, got)
}

func TestAESAutoKeyConversionKeepsRawExportSelection(t *testing.T) {
	t.Parallel()
	primary := bytes.Repeat([]byte{0x41}, 32)
	selected := bytes.Repeat([]byte{0x42}, 16)
	keyset := &tink_go_proto.Keyset{
		PrimaryKeyId: 101,
		Key: []*tink_go_proto.Keyset_Key{
			fixtureAESKey(t, 101, primary, tink_go_proto.KeyStatusType_ENABLED),
			fixtureAESKey(t, 202, selected, tink_go_proto.KeyStatusType_ENABLED),
		},
	}
	input := writeAESKeysetFixture(t, keyset)
	output := filepath.Join(t.TempDir(), "raw.key")
	require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))
	_, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-convert", "--to", "raw", "--input", input, "--output", output)
	require.Error(t, err)
	got, readErr := os.ReadFile(output)
	require.NoError(t, readErr)
	require.Equal(t, []byte("preserve"), got)

	_, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-convert", "--to", "raw", "--key-id", "202", "--input", input, "--output", output)
	require.NoError(t, err)
	got, readErr = os.ReadFile(output)
	require.NoError(t, readErr)
	require.Equal(t, selected, got)
}
