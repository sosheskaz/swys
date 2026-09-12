package crypter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func FuzzAESGCMDecrypt(f *testing.F) {
	key := make([]byte, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		f.Fatal(err)
	}
	oracle, err := cipher.NewGCM(block)
	if err != nil {
		f.Fatal(err)
	}
	nonce := make([]byte, oracle.NonceSize())
	valid := oracle.Seal(bytes.Clone(nonce), nonce, []byte("authenticated plaintext"), []byte("aad"))
	f.Add(valid, []byte("aad"))
	f.Add(valid, []byte("wrong aad"))
	f.Add([]byte{}, []byte{})
	f.Add(valid[:27], []byte("aad"))
	f.Add(valid[:28], []byte("aad"))
	f.Add(make([]byte, 28), []byte{})
	f.Fuzz(func(t *testing.T, wire, aad []byte) {
		if len(wire) > 4096 || len(aad) > 4096 {
			t.Skip()
		}
		for _, input := range []io.Reader{
			bytes.NewReader(wire),
			iotest.OneByteReader(bytes.NewReader(wire)),
		} {
			crypter, createErr := NewAESGCMCrypter(key)
			if createErr != nil {
				t.Fatal(createErr)
			}
			var output bytes.Buffer
			decryptErr := crypter.Decrypt(input, &output, aad)
			if len(wire) < 28 {
				if !errors.Is(decryptErr, ErrMalformedCiphertext) || output.Len() != 0 {
					t.Fatal("malformed ciphertext must fail without plaintext")
				}
				continue
			}
			want, openErr := oracle.Open(nil, wire[:oracle.NonceSize()], wire[oracle.NonceSize():], aad)
			if openErr != nil {
				if !errors.Is(decryptErr, ErrAuthenticationFailed) || output.Len() != 0 {
					t.Fatal("unauthenticated ciphertext must fail without plaintext")
				}
				continue
			}
			if decryptErr != nil || !bytes.Equal(output.Bytes(), want) {
				t.Fatalf("authenticated plaintext differs from stdlib: %v", decryptErr)
			}
		}
	})
}
