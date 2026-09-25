package key

import (
	"bytes"
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/internal/crypter"
)

var (
	errKeyTestReadFailed = errors.New("read failed")
	errTestWriteFailed   = errors.New("write failed")
)

func TestGenerateAESKeyRejectsInvalidSizeBeforeWriting(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	if err := generateAESKey(64, &output); !errors.Is(err, crypter.ErrInvalidAESKeySize) {
		t.Fatalf("generateAESKey error = %v, want crypter.ErrInvalidAESKeySize", err)
	}
	assert.Empty(t, output.Bytes(), "generateAESKey wrote %d bytes before validation", output.Len())
}

func TestReadAndWriteKeyBytesPreserveIOErrors(t *testing.T) {
	t.Parallel()
	readCommand := &cobra.Command{}
	readCommand.SetIn(keyFailingReader{err: errKeyTestReadFailed})
	if _, err := readKey(readCommand); !errors.Is(err, errKeyTestReadFailed) {
		t.Fatalf("read error = %v, want reader failure", err)
	}

	writeCommand := &cobra.Command{}
	writeCommand.SetOut(keyFailingWriter{err: errTestWriteFailed})
	if err := writeKeyBytes(writeCommand, []byte("key"), "test key"); !errors.Is(err, errTestWriteFailed) {
		t.Fatalf("write error = %v, want writer failure", err)
	}
}

type keyFailingReader struct{ err error }

func (reader keyFailingReader) Read([]byte) (int, error) { return 0, reader.err }

type keyFailingWriter struct{ err error }

func (writer keyFailingWriter) Write([]byte) (int, error) { return 0, writer.err }

func TestKeyGenerateAcceptsLongAlgorithmNames(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"aes128":  "aes-128",
		"aes256":  "aes-256",
		"p256":    "ecdsa-p256",
		"p384":    "ecdsa-p384",
		"rsa2048": "rsa-2048",
		"rsa4096": "rsa-4096",
	}
	for shortName, longName := range tests {
		shortAlgorithm, err := keyAlgorithmFromName(shortName)
		require.NoError(t, err)
		longAlgorithm, err := keyAlgorithmFromName(longName)
		require.NoError(t, err)
		if longAlgorithm != shortAlgorithm {
			t.Fatalf("algorithm %q = %+v, want %q = %+v", longName, longAlgorithm, shortName, shortAlgorithm)
		}
	}
}
