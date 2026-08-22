package crypter

import (
	"bytes"
	"encoding/hex"
	"testing"
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
	if err != nil {
		t.Fatal(err)
	}

	var encrypted bytes.Buffer
	if err := crypter.Encrypt(iv, bytes.NewBufferString(cbcCompatibilityPlaintext), &encrypted); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encrypted.Bytes(), wire) {
		t.Fatalf("CBC compatibility ciphertext = %x, want %x", encrypted.Bytes(), wire)
	}

	var decrypted bytes.Buffer
	if err := crypter.Decrypt(bytes.NewReader(wire), &decrypted); err != nil {
		t.Fatal(err)
	}
	if decrypted.String() != cbcCompatibilityPlaintext {
		t.Fatalf("CBC compatibility plaintext = %q, want %q", decrypted.String(), cbcCompatibilityPlaintext)
	}
}

func decodeCompatibilityHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
