package crypter

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	cbcCompatibilityKeyHex    = "000102030405060708090a0b0c0d0e0f"
	cbcCompatibilityIVHex     = "101112131415161718191a1b1c1d1e1f"
	cbcCompatibilityPlaintext = "NPC AES-CBC compatibility fixture"
	cbcCompatibilityCipherHex = "101112131415161718191a1b1c1d1e1feb98dca3cec8355c01355a5efd0497ac2982948d8e2027237af387ed301652c64da5a753179be260a2bc666a3fbd8080"
)

func TestAESCBCCompatibilityFixture(t *testing.T) {
	t.Parallel()

	key := decodeCompatibilityHex(t, cbcCompatibilityKeyHex)
	iv := decodeCompatibilityHex(t, cbcCompatibilityIVHex)
	wire := decodeCompatibilityHex(t, cbcCompatibilityCipherHex)
	crypter, err := NewAESCrypter(key)
	require.NoError(t, err)

	var encrypted bytes.Buffer
	require.NoError(t, crypter.Encrypt(iv, bytes.NewBufferString(cbcCompatibilityPlaintext), &encrypted))
	assert.Equal(t, wire, encrypted.Bytes(), "CBC compatibility ciphertext")

	var decrypted bytes.Buffer
	require.NoError(t, crypter.Decrypt(bytes.NewReader(wire), &decrypted))
	assert.Equal(t, cbcCompatibilityPlaintext, decrypted.String(), "CBC compatibility plaintext")
}

func decodeCompatibilityHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	require.NoError(t, err)
	return decoded
}
