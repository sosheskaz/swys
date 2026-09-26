package key

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"
)

var (
	errKeyTestReadFailed = errors.New("read failed")
	errTestWriteFailed   = errors.New("write failed")
)

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
