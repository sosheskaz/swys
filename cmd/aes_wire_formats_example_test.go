package cmd_test

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"

	rootcmd "github.com/sosheskaz-systems/npc/cmd"
	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
)

func TestExampleAESAutodetectsKeysetFiles(t *testing.T) {
	t.Parallel()
	primary := bytes.Repeat([]byte{0x41}, 32)
	fixture := &tink_go_proto.Keyset{
		PrimaryKeyId: 101,
		Key: []*tink_go_proto.Keyset_Key{
			fixtureAESKey(t, 101, primary, tink_go_proto.KeyStatusType_ENABLED),
		},
	}
	plaintext := []byte("encrypt with a keyset file\n")
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "JSON with leading whitespace", data: append([]byte(" \n\t"), jsonAESFixture(t, fixture)...)},
		{name: "binary", data: mustMarshalAESKeyset(t, fixture)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			keyfile := filepath.Join(t.TempDir(), "keyfile")
			require.NoError(t, os.WriteFile(keyfile, tc.data, 0o600))
			wire, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(plaintext),
				"aes", "encrypt", "-K", keyfile)
			require.NoError(t, err)
			opened, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(wire),
				"aes", "decrypt", "-K", keyfile)
			require.NoError(t, err)
			require.Equal(t, plaintext, opened)
		})
	}
}

func TestExampleAESOpenPGPDefaultWire(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	plaintext := []byte{0, 'O', 'p', 'e', 'n', 'P', 'G', 'P', '\n', 0xff}
	keyArg := base64.StdEncoding.EncodeToString(key)
	wire, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(plaintext),
		"aes", "encrypt", "--key", keyArg)
	require.NoError(t, err)
	require.NotEmpty(t, wire)
	require.False(t, bytes.HasPrefix(wire, []byte("NPCENC\r\n")), "default output must use an OpenPGP packet stream")
	opened, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(wire),
		"aes", "decrypt", "--wire-format", "openpgp", "--key", keyArg)
	require.NoError(t, err)
	require.Equal(t, plaintext, opened)
}

func TestExampleAESTinkWireInteroperatesWithNativeTink(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x36}, 32)
	keyArg := base64.StdEncoding.EncodeToString(key)
	plaintext := []byte("binary\x00Tink\xffstream")
	aad := "example context"
	primitive, err := subtle.NewAESGCMHKDF(key, "SHA256", 32, 64, 0)
	require.NoError(t, err)

	wire, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(plaintext),
		"aes", "encrypt", "--wire-format", "tink", "--key", keyArg,
		"--chunk-size", "64", "--aad", aad)
	require.NoError(t, err)
	reader, err := primitive.NewDecryptingReader(bytes.NewReader(wire), []byte(aad))
	require.NoError(t, err)
	opened, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, plaintext, opened)

	var nativeWire bytes.Buffer
	writer, err := primitive.NewEncryptingWriter(&nativeWire, []byte(aad))
	require.NoError(t, err)
	n, err := writer.Write(plaintext)
	require.NoError(t, err)
	require.Equal(t, len(plaintext), n)
	require.NoError(t, writer.Close())
	opened, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(nativeWire.Bytes()),
		"aes", "decrypt", "--wire-format", "tink", "--key", keyArg,
		"--chunk-size", "64", "--aad", aad)
	require.NoError(t, err)
	require.Equal(t, plaintext, opened)
}

func TestExampleAESOpenPGPDecryptsSequoiaFixture(t *testing.T) {
	t.Parallel()
	keyArg := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	for _, test := range []struct {
		name      string
		plaintext []byte
	}{
		{name: "sequoia-aes256-gcm.pgp", plaintext: []byte{0, 'O', 'p', 'e', 'n', 'P', 'G', 'P', '\n', 0xff}},
		{name: "sequoia-text.pgp", plaintext: []byte("line one\r\nline two\n")},
		{name: "sequoia-compressed.pgp", plaintext: []byte{0, 'O', 'p', 'e', 'n', 'P', 'G', 'P', '\n', 0xff}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			wire := readSequoiaFixture(t, test.name)
			opened, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(wire),
				"aes", "decrypt", "--wire-format", "openpgp", "--key", keyArg)
			require.NoError(t, err)
			require.Equal(t, test.plaintext, opened)
		})
	}
}

func TestAESOpenPGPRejectsUnauthenticatedAndExtraPackets(t *testing.T) {
	t.Parallel()
	wire := readSequoiaFixture(t, "sequoia-aes256-gcm.pgp")
	keyArg := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	plaintext := []byte{0, 'O', 'p', 'e', 'n', 'P', 'G', 'P', '\n', 0xff}
	corruptTag := bytes.Clone(wire)
	corruptTag[len(corruptTag)-1] ^= 1
	longerPacket := bytes.Clone(wire)
	require.Equal(t, len(wire)-2, int(longerPacket[1]), "fixture expects a one-octet outer packet length")
	longerPacket[1]++

	for _, test := range []struct {
		name      string
		wire      []byte
		mayPrefix bool
	}{
		{name: "tampered final tag", wire: corruptTag, mayPrefix: true},
		{name: "truncated final tag", wire: wire[:len(wire)-1], mayPrefix: true},
		{name: "declared length beyond input", wire: longerPacket, mayPrefix: true},
		{name: "outer second packet", wire: append(bytes.Clone(wire), wire...), mayPrefix: true},
		{name: "inner second literal", wire: readSequoiaFixture(t, "sequoia-two-literals.pgp"), mayPrefix: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			opened, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(test.wire),
				"aes", "decrypt", "--wire-format", "openpgp", "--key", keyArg)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "unknown flag", "decryption must examine the selected wire format")
			if test.mayPrefix {
				require.True(t, bytes.HasPrefix(plaintext, opened), "only the first literal may reach output")
			} else {
				require.Empty(t, opened, "unauthenticated plaintext reached output")
			}
		})
	}
}

func readSequoiaFixture(t *testing.T, name string) []byte {
	t.Helper()
	wire, err := os.ReadFile(filepath.Join("..", "tests", "interop", "openpgp", "testdata", name))
	require.NoError(t, err)
	return wire
}
