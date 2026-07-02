package crypter

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"

	"github.com/sosheskaz-systems/npc/internal/sys"
)

const cryptBufferSize = 64 * 1024

var errInvalidPadding = errors.New("invalid PKCS#7 padding")

// AESCrypter encrypts and decrypts AES-CBC streams using PKCS#7 padding.
type AESCrypter struct {
	cipher     cipher.Block
	bufferSize int
}

// NewAESCrypter constructs an AES crypter from a 16-, 24-, or 32-byte key.
func NewAESCrypter(key []byte) (*AESCrypter, error) {
	return newAESCrypter(key, cryptBufferSize)
}

func newAESCrypter(key []byte, bufferSize int) (*AESCrypter, error) {
	if bufferSize <= 0 || bufferSize%aes.BlockSize != 0 {
		return nil, fmt.Errorf("buffer size must be a positive multiple of %d, got %d", aes.BlockSize, bufferSize)
	}
	sys.Log().V(1).Info("creating new AES crypter", "bits", len(key)*8)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	return &AESCrypter{cipher: block, bufferSize: bufferSize}, nil
}

// Encrypt writes the IV followed by AES-CBC ciphertext for plaintext.
func (a *AESCrypter) Encrypt(iv []byte, plaintext io.Reader, ciphertext io.Writer) error {
	if len(iv) != a.cipher.BlockSize() {
		return fmt.Errorf("IV must be %d bytes, got %d", a.cipher.BlockSize(), len(iv))
	}
	if err := writeAll(ciphertext, iv); err != nil {
		return fmt.Errorf("write IV: %w", err)
	}

	stream := cipher.NewCBCEncrypter(a.cipher, iv)
	buffer := make([]byte, a.bufferSize+aes.BlockSize)
	for {
		n, err := io.ReadFull(plaintext, buffer[:a.bufferSize])
		switch {
		case err == nil:
			stream.CryptBlocks(buffer[:n], buffer[:n])
			if err := writeAll(ciphertext, buffer[:n]); err != nil {
				return fmt.Errorf("write ciphertext: %w", err)
			}
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			paddingLen := aes.BlockSize - n%aes.BlockSize
			for i := range paddingLen {
				buffer[n+i] = byte(paddingLen)
			}
			finalLen := n + paddingLen
			stream.CryptBlocks(buffer[:finalLen], buffer[:finalLen])
			if err := writeAll(ciphertext, buffer[:finalLen]); err != nil {
				return fmt.Errorf("write final ciphertext block: %w", err)
			}
			return nil
		default:
			return fmt.Errorf("read plaintext: %w", err)
		}
	}
}

// Decrypt reads an IV-prefixed AES-CBC stream and writes unpadded plaintext.
func (a *AESCrypter) Decrypt(ciphertext io.Reader, plaintext io.Writer) error {
	iv := make([]byte, a.cipher.BlockSize())
	if _, err := io.ReadFull(ciphertext, iv); err != nil {
		return fmt.Errorf("read IV: %w", err)
	}

	stream := cipher.NewCBCDecrypter(a.cipher, iv)
	current := make([]byte, a.bufferSize)
	previous := make([]byte, a.bufferSize)
	previousLen := 0

	for {
		n, err := io.ReadFull(ciphertext, current)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("read ciphertext: %w", err)
		}
		if n%aes.BlockSize != 0 {
			return fmt.Errorf("ciphertext chunk is %d bytes; expected a multiple of %d", n, aes.BlockSize)
		}
		if n > 0 {
			stream.CryptBlocks(current[:n], current[:n])
			if previousLen > 0 {
				if writeErr := writeAll(plaintext, previous[:previousLen]); writeErr != nil {
					return fmt.Errorf("write plaintext: %w", writeErr)
				}
			}
			current, previous = previous, current
			previousLen = n
		}

		switch {
		case err == nil:
			continue
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			if previousLen == 0 {
				return errors.New("ciphertext contains an IV but no encrypted data")
			}
			unpadded, paddingErr := unpadPKCS7(previous[:previousLen], aes.BlockSize)
			if paddingErr != nil {
				return paddingErr
			}
			if writeErr := writeAll(plaintext, unpadded); writeErr != nil {
				return fmt.Errorf("write final plaintext block: %w", writeErr)
			}
			return nil
		}
	}
}

func unpadPKCS7(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errInvalidPadding
	}

	paddingLen := int(data[len(data)-1])
	if paddingLen == 0 || paddingLen > blockSize {
		return nil, errInvalidPadding
	}
	for _, value := range data[len(data)-paddingLen:] {
		if int(value) != paddingLen {
			return nil, errInvalidPadding
		}
	}
	return data[:len(data)-paddingLen], nil
}

func writeAll(writer io.Writer, data []byte) error {
	written, err := writer.Write(data)
	if err != nil {
		return fmt.Errorf("write data: %w", err)
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return nil
}
