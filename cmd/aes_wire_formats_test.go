package cmd_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
	"google.golang.org/protobuf/proto"

	rootcmd "github.com/sosheskaz/swys/cmd"
	"github.com/sosheskaz/swys/cmd/internal/cli/artifact"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

func TestAESOpenPGPSelectsNamedKeysetEntry(t *testing.T) {
	t.Parallel()
	first := bytes.Repeat([]byte{0x41}, 32)
	selected := bytes.Repeat([]byte{0x42}, 16)
	fixture := &tink_go_proto.Keyset{
		PrimaryKeyId: 101,
		Key: []*tink_go_proto.Keyset_Key{
			fixtureAESKey(t, 101, first, tink_go_proto.KeyStatusType_ENABLED),
			fixtureAESKey(t, 202, selected, tink_go_proto.KeyStatusType_ENABLED),
		},
	}
	keyPath := writeAESKeysetFixture(t, fixture)
	plaintext := []byte("selected OpenPGP session key")
	baseArgs := []string{"aes", "encrypt", "--wire-format", "openpgp", "--key", keyPath, "--key-format", "tink-json"}
	primaryWire, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(plaintext), baseArgs...)
	require.NoError(t, err, "OpenPGP defaults to the enabled primary key")
	primaryOpened, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(primaryWire),
		"aes", "decrypt", "--key-base64", base64.StdEncoding.EncodeToString(first))
	require.NoError(t, err)
	require.Equal(t, plaintext, primaryOpened)
	primaryOpened, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(primaryWire),
		"aes", "decrypt", "--key", keyPath, "--key-format", "tink-json")
	require.NoError(t, err)
	require.Equal(t, plaintext, primaryOpened)

	wire, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(plaintext),
		append(slices.Clone(baseArgs), "--key-id", "202")...)
	require.NoError(t, err)
	opened, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(wire),
		"aes", "decrypt", "--wire-format", "openpgp", "--key-base64", base64.StdEncoding.EncodeToString(selected))
	require.NoError(t, err)
	require.Equal(t, plaintext, opened)
	opened, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(wire),
		"aes", "decrypt", "--key", keyPath, "--key-format", "tink-json")
	require.Error(t, err, "old ciphertext needs the older key ID after rotation")
	require.Empty(t, opened)
	opened, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(wire),
		"aes", "decrypt", "--key", keyPath, "--key-format", "tink-json", "--key-id", "202")
	require.NoError(t, err)
	require.Equal(t, plaintext, opened)
}

func mustMarshalAESKeyset(t *testing.T, keyset *tink_go_proto.Keyset) []byte {
	t.Helper()
	data, err := proto.Marshal(keyset)
	require.NoError(t, err)
	return data
}

func TestAESAutoKeyfilePreservesValidRawKeys(t *testing.T) {
	t.Parallel()
	for _, size := range []int{16, 32} {
		t.Run(fmt.Sprintf("%d bytes", size), func(t *testing.T) {
			t.Parallel()
			key := bytes.Repeat([]byte{' '}, size)
			copy(key, " {\"key\":")
			path := filepath.Join(t.TempDir(), "looks-like-json")
			require.NoError(t, os.WriteFile(path, key, 0o600))
			plaintext := []byte("raw key precedence")
			wire, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(plaintext),
				"aes", "encrypt", "--key", path)
			require.NoError(t, err)
			opened, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(wire),
				"aes", "decrypt", "--key", path)
			require.NoError(t, err)
			require.Equal(t, plaintext, opened)
		})
	}
}

func TestAESAutoKeyfileRejectsInvalidSelectionsBeforeOutput(t *testing.T) {
	t.Parallel()
	primary := bytes.Repeat([]byte{0x41}, 32)
	fixture := &tink_go_proto.Keyset{
		PrimaryKeyId: 101,
		Key: []*tink_go_proto.Keyset_Key{
			fixtureAESKey(t, 101, primary, tink_go_proto.KeyStatusType_ENABLED),
			fixtureAESKey(t, 202, bytes.Repeat([]byte{0x42}, 32), tink_go_proto.KeyStatusType_DISABLED),
		},
	}
	jsonKeyset := jsonAESFixture(t, fixture)
	for _, tc := range []struct {
		name  string
		data  []byte
		flags []string
	}{
		{name: "explicit raw does not detect JSON", data: jsonKeyset, flags: []string{"--key-format", "raw"}},
		{name: "explicit JSON does not detect raw", data: primary, flags: []string{"--key-format", "tink-json"}},
		{name: "disabled key ID", data: jsonKeyset, flags: []string{"--key-id", "202"}},
		{name: "unknown key ID", data: jsonKeyset, flags: []string{"--key-id", "303"}},
		{name: "raw key with key ID", data: primary, flags: []string{"--key-id", "101"}},
		{name: "malformed JSON", data: []byte(" {\"secret\":\"KEY_MATERIAL_SENTINEL\",")},
		{name: "oversized keyfile", data: bytes.Repeat([]byte{'x'}, int(artifact.MaxKeyBytes)+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			keyfile := filepath.Join(t.TempDir(), "keyfile")
			output := filepath.Join(t.TempDir(), "output")
			require.NoError(t, os.WriteFile(keyfile, tc.data, 0o600))
			require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))
			args := append([]string{"aes", "encrypt", "--key", keyfile, "--output", output}, tc.flags...)
			_, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader([]byte("payload")), args...)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "KEY_MATERIAL_SENTINEL")
			contents, readErr := os.ReadFile(output)
			require.NoError(t, readErr)
			require.Equal(t, []byte("preserve"), contents)
		})
	}
}

func TestAESTinkKeysetUsesNativePrimaryAndParameters(t *testing.T) {
	t.Parallel()
	material := bytes.Repeat([]byte{0x51}, 32)
	fixture := &tink_go_proto.Keyset{
		PrimaryKeyId: 101,
		Key: []*tink_go_proto.Keyset_Key{
			fixtureAESKey(t, 101, material, tink_go_proto.KeyStatusType_ENABLED),
			fixtureAESKey(t, 202, bytes.Repeat([]byte{0x52}, 16), tink_go_proto.KeyStatusType_ENABLED),
		},
	}
	keyPath := writeAESKeysetFixture(t, fixture)
	primitive, err := streamingaead.New(readNativeAESKeyset(t, keyPath, "tink-json"))
	require.NoError(t, err)
	plaintext := []byte("Tink keyset stream\x00")
	aad := []byte("context")

	wire, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(plaintext),
		"aes", "encrypt", "--wire-format", "tink", "--key", keyPath,
		"--aad", string(aad))
	require.NoError(t, err)
	reader, err := primitive.NewDecryptingReader(bytes.NewReader(wire), aad)
	require.NoError(t, err)
	opened, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, plaintext, opened)

	rotated := new(tink_go_proto.Keyset)
	proto.Merge(rotated, fixture)
	rotated.PrimaryKeyId = 202
	rotatedPath := writeAESKeysetFixture(t, rotated)
	rotatedPrimitive, err := streamingaead.New(readNativeAESKeyset(t, rotatedPath, "tink-json"))
	require.NoError(t, err)
	var nativeWire bytes.Buffer
	writer, err := rotatedPrimitive.NewEncryptingWriter(&nativeWire, aad)
	require.NoError(t, err)
	_, err = writer.Write(plaintext)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	opened, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(nativeWire.Bytes()),
		"aes", "decrypt", "--wire-format", "tink", "--key", keyPath,
		"--aad", string(aad))
	require.NoError(t, err)
	require.Equal(t, plaintext, opened)

	_, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(plaintext),
		"aes", "encrypt", "--wire-format", "tink", "--key", keyPath,
		"--key-format", "tink-json", "--chunk-size", "64")
	require.Error(t, err, "explicit parameters must agree with the keyset")
}

func TestAESTinkKeysetMatchesKeyBeforeOutput(t *testing.T) {
	t.Parallel()
	fixture := &tink_go_proto.Keyset{
		PrimaryKeyId: 101,
		Key:          []*tink_go_proto.Keyset_Key{fixtureAESKey(t, 101, bytes.Repeat([]byte{0x53}, 32), tink_go_proto.KeyStatusType_ENABLED)},
	}
	keyArgs := []string{"--wire-format", "tink", "--key", writeAESKeysetFixture(t, fixture), "--key-format", "tink-json"}
	output := filepath.Join(t.TempDir(), "plaintext")
	require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))
	_, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader([]byte("not a Tink header")),
		append([]string{"aes", "decrypt", "--output", output}, keyArgs...)...)
	require.ErrorContains(t, err, "decrypt Tink stream")
	contents, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, []byte("preserve"), contents, "unmatched keyset ciphertext mutated output")

	// Spans the 1 MiB segment boundary to catch bytes lost around the first read.
	long := make([]byte, 1<<20+777)
	_, _ = rand.New(rand.NewSource(53)).Read(long)
	for _, plaintext := range [][]byte{{}, long} {
		wire, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(plaintext),
			append([]string{"aes", "encrypt"}, keyArgs...)...)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))
		_, _, err = testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(wire),
			append([]string{"aes", "decrypt", "--output", output}, keyArgs...)...)
		require.NoError(t, err)
		opened, err := os.ReadFile(output)
		require.NoError(t, err)
		require.Equal(t, plaintext, opened)
	}
}

func TestAESTinkRejectsUnauthenticatedSegments(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x36}, 32)
	plaintext := bytes.Repeat([]byte("authenticated segment\x00"), 16)
	aad := "context"
	primitive, err := subtle.NewAESGCMHKDF(key, "SHA256", 32, 64, 0)
	require.NoError(t, err)
	var nativeWire bytes.Buffer
	writer, err := primitive.NewEncryptingWriter(&nativeWire, []byte(aad))
	require.NoError(t, err)
	n, err := writer.Write(plaintext)
	require.NoError(t, err)
	require.Equal(t, len(plaintext), n)
	require.NoError(t, writer.Close())
	wire := nativeWire.Bytes()
	require.NotEmpty(t, wire)
	tamperedFinal := bytes.Clone(wire)
	tamperedFinal[len(tamperedFinal)-1] ^= 1

	for _, test := range []struct {
		name     string
		aad      string
		wire     []byte
		key      []byte
		firstBad bool
	}{
		{name: "wrong AAD", wire: wire, key: key, aad: "wrong", firstBad: true},
		{name: "wrong key", wire: wire, key: bytes.Repeat([]byte{0x37}, 32), aad: aad, firstBad: true},
		{name: "tampered final segment", wire: tamperedFinal, key: key, aad: aad},
		{name: "truncated final segment", wire: wire[:len(wire)-1], key: key, aad: aad},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			opened, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(test.wire),
				"aes", "decrypt", "--wire-format", "tink", "--key-base64", base64.StdEncoding.EncodeToString(test.key),
				"--chunk-size", "64", "--aad", test.aad)
			require.Error(t, err)
			if test.firstBad {
				require.Empty(t, opened, "unauthenticated first segment reached output")
				return
			}
			require.True(t, bytes.HasPrefix(plaintext, opened), "only authenticated segments may reach output")
			require.Less(t, len(opened), len(plaintext), "unauthenticated final segment reached output")
		})
	}
}

func TestAESOpenPGPPreparesCompressedInputBeforeOutput(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, 32)
	plaintext := make([]byte, 64<<10)
	_, err := rand.New(rand.NewSource(3)).Read(plaintext)
	require.NoError(t, err)
	encryptedWriter := func(wire *bytes.Buffer, chunk uint64) io.WriteCloser {
		writer, err := packet.SerializeSymmetricallyEncrypted(wire, 0, true,
			packet.CipherSuite{Cipher: packet.CipherAES256, Mode: packet.AEADModeGCM},
			key, &packet.Config{AEADConfig: &packet.AEADConfig{ChunkSize: chunk}})
		require.NoError(t, err)
		return writer
	}

	var small bytes.Buffer
	compressed, err := packet.SerializeCompressed(encryptedWriter(&small, 64), packet.CompressionZIP, nil)
	require.NoError(t, err)
	literal, err := packet.SerializeLiteral(compressed, true, "", 0)
	require.NoError(t, err)
	_, err = literal.Write(plaintext)
	require.NoError(t, err)
	require.NoError(t, literal.Close())

	// A ZIP packet expanding to 8 MiB of empty DEFLATE blocks before its literal.
	var bomb bytes.Buffer
	outer, err := packet.SerializeCompressed(encryptedWriter(&bomb, 1<<20), packet.CompressionZIP,
		&packet.CompressionConfig{Level: 9})
	require.NoError(t, err)
	_, err = outer.Write([]byte{0xa3, 1})
	require.NoError(t, err)
	emptyBlocks := bytes.Repeat([]byte{0, 0, 0, 0xff, 0xff}, 4096)
	for range (8 << 20) / len(emptyBlocks) {
		_, err = outer.Write(emptyBlocks)
		require.NoError(t, err)
	}
	_, err = outer.Write([]byte{1, 8, 0, 0xf7, 0xff, 0xcb, 6, 'b', 0, 0, 0, 0, 0})
	require.NoError(t, err)
	require.NoError(t, outer.Close())

	for _, test := range []struct {
		name    string
		wantErr string
		wire    []byte
		want    []byte
	}{
		{name: "small AEAD chunks", wire: small.Bytes(), want: plaintext},
		{
			name: "nested expansion over budget", wire: bomb.Bytes(), want: []byte("preserve"),
			wantErr: "OpenPGP header exceeds preparation limit",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output := filepath.Join(t.TempDir(), "plaintext")
			require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))
			_, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(test.wire),
				"aes", "decrypt", "--key-base64", base64.StdEncoding.EncodeToString(key), "--output", output)
			if test.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantErr)
			}
			contents, readErr := os.ReadFile(output)
			require.NoError(t, readErr)
			require.Equal(t, test.want, contents)
		})
	}
}

func TestAESWireValidationPreservesOutput(t *testing.T) {
	t.Parallel()
	keyArg := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	for _, test := range []struct {
		name    string
		flags   []string
		decrypt bool
	}{
		{name: "OpenPGP external AAD", flags: []string{"--aad", "context"}},
		{name: "OpenPGP nonpower chunk", flags: []string{"--chunk-size", "96"}},
		{name: "raw key with keyset ID", flags: []string{"--key-id", "not-a-number"}},
		{name: "OpenPGP decrypt chunk override", flags: []string{"--chunk-size", "64"}, decrypt: true},
		{name: "legacy raw selector", flags: []string{"--raw"}},
		{name: "legacy CBC selector", flags: []string{"--cipher-mode", "cbc"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output := filepath.Join(t.TempDir(), "preserved")
			require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))
			leaf := "encrypt"
			if test.decrypt {
				leaf = "decrypt"
			}
			args := []string{"aes", leaf, "--key-base64", keyArg, "--output", output}
			args = append(args, test.flags...)
			input := []byte("payload")
			if test.decrypt {
				input = readSequoiaFixture(t, "sequoia-aes256-gcm.pgp")
			}
			_, _, err := testcmd.RunStreams(t, rootcmd.NewCommand(), bytes.NewReader(input), args...)
			require.Error(t, err)
			contents, readErr := os.ReadFile(output)
			require.NoError(t, readErr)
			require.Equal(t, []byte("preserve"), contents)
		})
	}
}
