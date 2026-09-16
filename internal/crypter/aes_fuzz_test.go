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

const (
	maxFuzzPaddingInputSize = 1 << 12
	// PKCS#7 encodes the pad length in a single byte, so block sizes are
	// generated below the point where that encoding stops being expressible.
	// The selector maps to its own value so seeds can name a block size directly.
	maxFuzzPaddingBlockSize = 32
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

// FuzzUnpadPKCS7 states the padding contract independently of how unpadPKCS7
// derives the pad length: a successful result is a prefix of its input whose
// removed suffix consists entirely of bytes equal to that suffix's own length.
// The roundTrip dimension supplies independently padded messages so an
// implementation that rejected everything could not pass.
func FuzzUnpadPKCS7(f *testing.F) {
	f.Add([]byte{}, uint8(aes.BlockSize), false)
	f.Add(bytes.Repeat([]byte{aes.BlockSize}, aes.BlockSize), uint8(aes.BlockSize), false)
	f.Add(append(bytes.Repeat([]byte{0xa5}, aes.BlockSize-1), 0x01), uint8(aes.BlockSize), false)
	f.Add(append(bytes.Repeat([]byte{0xa5}, aes.BlockSize-1), 0x00), uint8(aes.BlockSize), false)
	f.Add(append(bytes.Repeat([]byte{0xa5}, aes.BlockSize-1), aes.BlockSize+1), uint8(aes.BlockSize), false)
	f.Add(append(bytes.Repeat([]byte{0x02}, aes.BlockSize-1), 0x02), uint8(aes.BlockSize), false)
	// Trailing bytes disagree with the declared pad length in every position but
	// the last, so an implementation that only inspects data[len(data)-1] accepts
	// it and strips bytes that were never padding.
	f.Add(append(bytes.Repeat([]byte{0xa5}, aes.BlockSize-2), 0x01, 0x02), uint8(aes.BlockSize), false)
	f.Add([]byte{0x01, 0x02, 0x03, 0x03, 0x03}, uint8(5), false)
	// Self-consistent trailing padding on a length that is not a block multiple:
	// only the block-multiple check can reject this.
	f.Add([]byte{0x01, 0x02, 0x02}, uint8(aes.BlockSize), false)
	f.Add([]byte{0x01, 0x03, 0x03}, uint8(3), false)
	f.Add([]byte{}, uint8(1), true)
	f.Add([]byte("exactly one block"), uint8(aes.BlockSize), true)
	f.Add(make([]byte, 3*aes.BlockSize), uint8(aes.BlockSize), true)

	f.Fuzz(func(t *testing.T, data []byte, blockSizeSelector uint8, roundTrip bool) {
		if len(data) > maxFuzzPaddingInputSize {
			t.Skip()
		}
		blockSize := max(int(blockSizeSelector)%(maxFuzzPaddingBlockSize+1), 1)
		if roundTrip {
			checkPKCS7RoundTrip(t, data, blockSize)
			return
		}

		unpadded, err := unpadPKCS7(data, blockSize)
		if err != nil {
			if unpadded != nil {
				t.Fatalf("rejected padding returned %x", unpadded)
			}
			if !errors.Is(err, errInvalidPadding) {
				t.Fatalf("error = %v, want invalid padding", err)
			}
			return
		}

		if len(data)%blockSize != 0 {
			t.Fatalf("accepted %d bytes, which is not a multiple of block size %d", len(data), blockSize)
		}
		if len(unpadded) >= len(data) {
			t.Fatalf("unpadded length %d did not shrink input length %d", len(unpadded), len(data))
		}
		if !bytes.Equal(unpadded, data[:len(unpadded)]) {
			t.Fatalf("unpadded %x is not a prefix of %x", unpadded, data)
		}
		stripped := data[len(unpadded):]
		if len(stripped) > blockSize {
			t.Fatalf("stripped %d bytes, more than block size %d", len(stripped), blockSize)
		}
		for index, value := range stripped {
			if int(value) != len(stripped) {
				t.Fatalf("stripped byte %d of %x is %#x, want the stripped length %d", index, stripped, value, len(stripped))
			}
		}
	})
}

func checkPKCS7RoundTrip(t *testing.T, message []byte, blockSize int) {
	t.Helper()
	padding := blockSize - len(message)%blockSize
	padded := append(bytes.Clone(message), bytes.Repeat([]byte{byte(padding)}, padding)...)
	unpadded, err := unpadPKCS7(padded, blockSize)
	if err != nil {
		t.Fatalf("independently padded %d-byte message rejected at block size %d: %v", len(message), blockSize, err)
	}
	if !bytes.Equal(unpadded, message) {
		t.Fatalf("round trip = %x, want %x", unpadded, message)
	}
}
