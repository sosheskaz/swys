package crypter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"

	"github.com/docker/go-units"
	"github.com/sosheskaz/cryptool/internal/sys"
)

const (
	cryptBufferSize = 64 * units.KiB
)

type AESCrypter struct {
	cipher cipher.Block
}

type AESCrypterConfig struct {
	BlockSize int
}

func NewAESCrypter(key []byte) (*AESCrypter, error) {
	sys.Log().V(0).Info("creating new AES crypter", "bits", len(key)*8)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &AESCrypter{
		cipher: block,
	}, nil
}

func (a *AESCrypter) Encrypt(iv []byte, plaintext io.Reader, ciphertext io.Writer) error {
	stream := cipher.NewCBCEncrypter(a.cipher, iv)

	// Write IV at the beginning of the ciphertext
	if _, err := ciphertext.Write(iv); err != nil {
		return err
	}

	input := make([]byte, cryptBufferSize)
	output := make([]byte, cryptBufferSize)

	var isEOF bool
	for !isEOF {
		n, err := io.ReadFull(plaintext, input)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			isEOF = true
		} else if err != nil {
			// return err
		}

		if n != 0 {
			// Grab the last full block, rounding up using integer division.
			resizeTo := ((n + aes.BlockSize - 1) / aes.BlockSize) * aes.BlockSize
			// Resize the buffers to the reduced size.
			input = input[:resizeTo]
			output = output[:resizeTo]
			padding := (len(input) - n)
			copy(input[n:], bytes.Repeat([]byte{byte(padding)}, padding))
		}

		stream.CryptBlocks(output, input)

		if _, err := ciphertext.Write(output); err != nil {
			return err
		}
	}

	return nil
}

func (a *AESCrypter) Decrypt(ciphertext io.Reader, plaintext io.Writer) error {
	bufSize := aes.BlockSize * 256
	input := make([]byte, bufSize)
	output := make([]byte, bufSize)

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(ciphertext, iv); err != nil {
		return err
	}
	stream := cipher.NewCBCDecrypter(a.cipher, iv)

	var isEOF bool
	for !isEOF {
		n, err := io.ReadFull(ciphertext, input)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			isEOF = true
		} else if err != nil {
			return err
		}

		if n == 0 {
			break
		} else if n < aes.BlockSize {
			return fmt.Errorf("ciphertext (%d bytes) is not a multiple of the block size (%d bytes)", n, aes.BlockSize)
		}

		stream.CryptBlocks(output, input)

		if _, err := plaintext.Write(output); err != nil {
			return err
		}
	}

	return nil
}
