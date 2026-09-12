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

func FuzzAESCBCDecrypt(f *testing.F) {
	key := []byte("0123456789abcdef0123456789abcdef")
	iv := []byte("fedcba9876543210")
	for _, plaintext := range [][]byte{
		nil,
		[]byte("one byte"),
		bytes.Repeat([]byte{0xa5}, aes.BlockSize),
		bytes.Repeat([]byte{0x5a}, 8*aes.BlockSize+1),
	} {
		f.Add(aesCBCWire(f, key, iv, plaintext), uint8(4))
	}
	f.Add([]byte{}, uint8(1))
	f.Add(bytes.Clone(iv), uint8(2))
	f.Add(append(bytes.Clone(iv), make([]byte, aes.BlockSize-1)...), uint8(3))

	f.Fuzz(func(t *testing.T, wire []byte, bufferBlocks uint8) {
		if len(wire) > 16<<10 {
			t.Skip()
		}
		bufferSize := (int(bufferBlocks)%16 + 1) * aes.BlockSize
		want, wantOutput, wantErr := aesCBCDecryptOracle(key, wire, bufferSize)

		for _, input := range []io.Reader{
			bytes.NewReader(wire),
			iotest.OneByteReader(bytes.NewReader(wire)),
		} {
			crypter, err := newAESCrypter(key, bufferSize)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			err = crypter.Decrypt(input, &output)
			if wantErr == nil {
				if err != nil {
					t.Fatalf("valid ciphertext failed: %v", err)
				}
				if !bytes.Equal(output.Bytes(), want) {
					t.Fatalf("plaintext differs from independent AES-CBC decode")
				}
				continue
			}
			if !errors.Is(err, wantErr) {
				t.Fatalf("error = %v, want %v", err, wantErr)
			}
			if !bytes.Equal(output.Bytes(), wantOutput) {
				t.Fatalf("failure output = %x, want streamed prefix %x", output.Bytes(), wantOutput)
			}
		}
	})
}

func aesCBCWire(tb testing.TB, key, iv, plaintext []byte) []byte {
	tb.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		tb.Fatal(err)
	}
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := append(bytes.Clone(plaintext), bytes.Repeat([]byte{byte(padding)}, padding)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(padded, padded)
	return append(bytes.Clone(iv), padded...)
}

func aesCBCDecryptOracle(key, wire []byte, bufferSize int) ([]byte, []byte, error) {
	if len(wire) < aes.BlockSize {
		if len(wire) == 0 {
			return nil, nil, io.EOF
		}
		return nil, nil, io.ErrUnexpectedEOF
	}
	body := wire[aes.BlockSize:]
	if len(body) == 0 {
		return nil, nil, errMissingCiphertextBody
	}

	aligned := len(body) - len(body)%aes.BlockSize
	decrypted := bytes.Clone(body[:aligned])
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(decrypted) != 0 {
		cipher.NewCBCDecrypter(block, wire[:aes.BlockSize]).CryptBlocks(decrypted, decrypted)
	}
	if aligned != len(body) {
		fullChunks := aligned / bufferSize
		writtenChunks := max(fullChunks-1, 0)
		return nil, decrypted[:writtenChunks*bufferSize], errMisalignedCiphertext
	}

	lastChunk := len(decrypted) % bufferSize
	if lastChunk == 0 {
		lastChunk = bufferSize
	}
	prefix := decrypted[:len(decrypted)-lastChunk]
	padding := int(decrypted[len(decrypted)-1])
	if padding == 0 || padding > aes.BlockSize {
		return nil, prefix, errInvalidPadding
	}
	for _, value := range decrypted[len(decrypted)-padding:] {
		if int(value) != padding {
			return nil, prefix, errInvalidPadding
		}
	}
	return decrypted[:len(decrypted)-padding], nil, nil
}
