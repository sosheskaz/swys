package crypter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"testing"

	"github.com/docker/go-units"
)

// Test different buffer sizes to find optimal value.
func BenchmarkBufferSizes(b *testing.B) {
	bufferSizes := []struct {
		name string
		size int
	}{
		{"4KB", 4 * units.KiB},
		{"8KB", 8 * units.KiB},
		{"16KB", 16 * units.KiB},
		{"32KB", 32 * units.KiB},
		{"64KB", 64 * units.KiB}, // current default
		{"128KB", 128 * units.KiB},
		{"256KB", 256 * units.KiB},
		{"512KB", 512 * units.KiB},
		{"1MB", 1024 * units.KiB},
	}

	// Test with 64MB of data to see real-world performance
	dataSize := 64 * 1024 * 1024

	for _, bufSize := range bufferSizes {
		b.Run("Encrypt_"+bufSize.name, func(b *testing.B) {
			key := make([]byte, 32)
			io.ReadFull(rand.Reader, key)
			block, _ := aes.NewCipher(key)

			plaintext := make([]byte, dataSize)
			io.ReadFull(rand.Reader, plaintext)

			iv := make([]byte, aes.BlockSize)
			io.ReadFull(rand.Reader, iv)

			b.ResetTimer()
			b.SetBytes(int64(dataSize))

			for range b.N {
				encryptWithBufferSize(block, iv, plaintext, bufSize.size)
			}
		})

		b.Run("Decrypt_"+bufSize.name, func(b *testing.B) {
			key := make([]byte, 32)
			io.ReadFull(rand.Reader, key)
			block, _ := aes.NewCipher(key)

			plaintext := make([]byte, dataSize)
			io.ReadFull(rand.Reader, plaintext)

			iv := make([]byte, aes.BlockSize)
			io.ReadFull(rand.Reader, iv)

			// Encrypt once to get ciphertext
			ciphertext := encryptWithBufferSize(block, iv, plaintext, bufSize.size)

			b.ResetTimer()
			b.SetBytes(int64(dataSize))

			for range b.N {
				decryptWithBufferSize(block, ciphertext, bufSize.size)
			}
		})
	}
}

func encryptWithBufferSize(block cipher.Block, iv, plaintext []byte, bufferSize int) []byte {
	stream := cipher.NewCBCEncrypter(block, iv)

	output := &bytes.Buffer{}
	output.Write(iv)

	inputBuf := make([]byte, bufferSize+aes.BlockSize)
	outputBuf := make([]byte, bufferSize+aes.BlockSize)

	leftoverBuf := make([]byte, aes.BlockSize)
	leftoverLen := 0

	reader := bytes.NewReader(plaintext)

	for {
		n, err := io.ReadFull(reader, inputBuf[leftoverLen:bufferSize])
		isEOF := err == io.EOF || err == io.ErrUnexpectedEOF

		if leftoverLen > 0 {
			copy(inputBuf, leftoverBuf[:leftoverLen])
			n += leftoverLen
			leftoverLen = 0
		}

		if n > 0 || isEOF {
			if isEOF {
				padding := aes.BlockSize - (n % aes.BlockSize)
				if padding == 0 {
					padding = aes.BlockSize
				}
				for i := range padding {
					inputBuf[n+i] = byte(padding)
				}
				resizeTo := n + padding
				stream.CryptBlocks(outputBuf[:resizeTo], inputBuf[:resizeTo])
				output.Write(outputBuf[:resizeTo])
				break
			} else if n >= aes.BlockSize {
				resizeTo := (n / aes.BlockSize) * aes.BlockSize
				remainder := n % aes.BlockSize
				stream.CryptBlocks(outputBuf[:resizeTo], inputBuf[:resizeTo])
				output.Write(outputBuf[:resizeTo])
				if remainder > 0 {
					copy(leftoverBuf, inputBuf[resizeTo:n])
					leftoverLen = remainder
				}
			} else {
				copy(leftoverBuf, inputBuf[:n])
				leftoverLen = n
			}
		}

		if isEOF {
			break
		}
	}

	return output.Bytes()
}

func decryptWithBufferSize(block cipher.Block, ciphertext []byte, bufferSize int) []byte {
	input := make([]byte, bufferSize)
	output := make([]byte, bufferSize)

	reader := bytes.NewReader(ciphertext)
	result := &bytes.Buffer{}

	iv := make([]byte, aes.BlockSize)
	io.ReadFull(reader, iv)
	stream := cipher.NewCBCDecrypter(block, iv)

	previousBlock := make([]byte, bufferSize)
	previousLen := 0
	hasPrevious := false

	for {
		n, err := io.ReadFull(reader, input)
		isEOF := err == io.EOF || err == io.ErrUnexpectedEOF

		if n == 0 {
			break
		}

		stream.CryptBlocks(output[:n], input[:n])

		if hasPrevious {
			result.Write(previousBlock[:previousLen])
		}

		output, previousBlock = previousBlock, output
		previousLen = n
		hasPrevious = true

		if isEOF {
			break
		}
	}

	if hasPrevious {
		paddingLen := int(previousBlock[previousLen-1])
		paddingStart := previousLen - paddingLen
		result.Write(previousBlock[:paddingStart])
	}

	return result.Bytes()
}
