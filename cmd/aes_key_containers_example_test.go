package cmd_test

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/proto/aes_gcm_hkdf_streaming_go_proto"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
	"google.golang.org/protobuf/proto"

	rootcmd "github.com/sosheskaz/swys/cmd"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

func TestExampleAESKeyContainerWorkflow(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "aes.json")
	binaryPath := filepath.Join(dir, "aes.bin")
	rawPath := filepath.Join(dir, "aes.key")

	_, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "keygen", "--key-format", "tink-json", "--output", jsonPath)
	require.NoError(t, err)
	jsonKeyset := readNativeAESKeyset(t, jsonPath, "tink-json")
	require.Len(t, jsonKeyset.KeysetInfo().KeyInfo, 1)
	require.NotZero(t, jsonKeyset.KeysetInfo().PrimaryKeyId)
	primitive, err := streamingaead.New(jsonKeyset)
	require.NoError(t, err, "generated keyset must instantiate Tink's native streaming primitive")
	var ciphertext bytes.Buffer
	writer, err := primitive.NewEncryptingWriter(&ciphertext, []byte("example AAD"))
	require.NoError(t, err)
	plaintext := []byte("standard Tink streaming keyset")
	n, err := writer.Write(plaintext)
	require.NoError(t, err)
	require.Equal(t, len(plaintext), n)
	require.NoError(t, writer.Close())
	reader, err := primitive.NewDecryptingReader(bytes.NewReader(ciphertext.Bytes()), []byte("example AAD"))
	require.NoError(t, err)
	opened, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, plaintext, opened)

	_, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-convert", "--from", "tink-json", "--to", "tink-binary",
		"--input", jsonPath, "--output", binaryPath)
	require.NoError(t, err)
	binaryKeyset := readNativeAESKeyset(t, binaryPath, "tink-binary")
	require.True(t, proto.Equal(insecurecleartextkeyset.KeysetMaterial(jsonKeyset), insecurecleartextkeyset.KeysetMaterial(binaryKeyset)))

	_, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-convert", "--from", "tink-binary", "--to", "raw",
		"--input", binaryPath, "--output", rawPath)
	require.NoError(t, err)
	raw, err := os.ReadFile(rawPath)
	require.NoError(t, err)
	require.Len(t, raw, 32)
	key := new(aes_gcm_hkdf_streaming_go_proto.AesGcmHkdfStreamingKey)
	require.NoError(t, proto.Unmarshal(insecurecleartextkeyset.KeysetMaterial(binaryKeyset).Key[0].KeyData.Value, key))
	require.True(t, bytes.Equal(key.KeyValue, raw), "raw export must preserve key material")

	inspection, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil,
		"aes", "key-inspect", "--key-format", "tink-json", "--input", jsonPath, "--format", "json")
	require.NoError(t, err)
	require.NotContains(t, string(inspection), string(raw), "inspection must not print key material")
	require.NotContains(t, string(inspection), base64.StdEncoding.EncodeToString(raw), "inspection must not print encoded key material")
}

func readNativeAESKeyset(t *testing.T, path, format string) *keyset.Handle {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var reader keyset.Reader
	switch format {
	case "tink-json":
		reader = keyset.NewJSONReader(bytes.NewReader(data))
	case "tink-binary":
		reader = keyset.NewBinaryReader(bytes.NewReader(data))
	default:
		t.Fatalf("unknown native keyset format %q", format)
	}
	handle, err := insecurecleartextkeyset.Read(reader)
	require.NoError(t, err)
	return handle
}
