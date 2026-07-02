package crypter

import (
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
	// Use V(1) so logging only occurs when verbosity is enabled
	sys.Log().V(1).Info("creating new AES crypter", "bits", len(key)*8)
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

	// Allocate buffers with extra space for padding (up to one block)
	inputBuf := make([]byte, cryptBufferSize+aes.BlockSize)
	outputBuf := make([]byte, cryptBufferSize+aes.BlockSize)

	// Pre-allocate leftover buffer to avoid allocations in the loop
	leftoverBuf := make([]byte, aes.BlockSize)
	leftoverLen := 0
	var isEOF bool

	for !isEOF {
		// Read into the buffer after any leftover bytes
		n, err := io.ReadFull(plaintext, inputBuf[leftoverLen:cryptBufferSize])
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			isEOF = true
		} else if err != nil {
			return err
		}

		// Prepend any leftover bytes from previous iteration
		if leftoverLen > 0 {
			copy(inputBuf, leftoverBuf[:leftoverLen])
			n += leftoverLen
			leftoverLen = 0
		}

		if n > 0 || isEOF {
			if isEOF {
				// Final chunk: add PKCS#7 padding
				padding := aes.BlockSize - (n % aes.BlockSize)
				if padding == 0 {
					padding = aes.BlockSize
				}

				for i := range padding {
					inputBuf[n+i] = byte(padding)
				}

				resizeTo := n + padding
				stream.CryptBlocks(outputBuf[:resizeTo], inputBuf[:resizeTo])

				if _, err := ciphertext.Write(outputBuf[:resizeTo]); err != nil {
					return err
				}
			} else if n >= aes.BlockSize {
				// Non-final chunk: encrypt only block-aligned data
				resizeTo := (n / aes.BlockSize) * aes.BlockSize
				remainder := n % aes.BlockSize

				stream.CryptBlocks(outputBuf[:resizeTo], inputBuf[:resizeTo])

				if _, err := ciphertext.Write(outputBuf[:resizeTo]); err != nil {
					return err
				}

				// Save any non-block-aligned bytes for next iteration
				if remainder > 0 {
					copy(leftoverBuf, inputBuf[resizeTo:n])
					leftoverLen = remainder
				}
			} else {
				// We have data but less than one block and not EOF
				// Save it for next iteration
				copy(leftoverBuf, inputBuf[:n])
				leftoverLen = n
			}
		}
	}

	return nil
}

func (a *AESCrypter) Decrypt(ciphertext io.Reader, plaintext io.Writer) error {
	bufSize := aes.BlockSize + cryptBufferSize
	input := make([]byte, bufSize)
	output := make([]byte, bufSize)

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(ciphertext, iv); err != nil {
		return err
	}
	stream := cipher.NewCBCDecrypter(a.cipher, iv)

	// Pre-allocate previousBlock buffer to avoid allocations in the loop
	previousBlock := make([]byte, bufSize)
	previousLen := 0
	hasPrevious := false
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
		}

		// Validate that we read a multiple of block size
		if n%aes.BlockSize != 0 {
			return fmt.Errorf("ciphertext (%d bytes) is not a multiple of the block size (%d bytes)", n, aes.BlockSize)
		}

		// Decrypt only the bytes we actually read
		stream.CryptBlocks(output[:n], input[:n])

		// If we have a previous block, write it now (it's not the last block)
		if hasPrevious {
			if _, err := plaintext.Write(previousBlock[:previousLen]); err != nil {
				return err
			}
		}

		// Swap buffers: output becomes previous, previous becomes output
		// This avoids allocation and copy
		output, previousBlock = previousBlock, output
		previousLen = n
		hasPrevious = true
	}

	// Handle the final block - strip PKCS#7 padding
	if hasPrevious {
		// Get padding length from the last byte
		paddingLen := int(previousBlock[previousLen-1])

		// Validate padding - must be between 1 and block size
		if paddingLen == 0 || paddingLen > aes.BlockSize {
			return fmt.Errorf("invalid padding length: %d", paddingLen)
		}

		// PKCS#7 padding is always within the last block only
		paddingStart := previousLen - paddingLen

		// Verify all padding bytes are correct
		for i := paddingStart; i < previousLen; i++ {
			if previousBlock[i] != byte(paddingLen) {
				return fmt.Errorf("invalid padding at position %d: expected %d, got %d", i, paddingLen, previousBlock[i])
			}
		}

		// Write the final block without padding
		if _, err := plaintext.Write(previousBlock[:paddingStart]); err != nil {
			return err
		}
	}

	return nil
}
