package cert

import (
	"bytes"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
	"github.com/sosheskaz-systems/npc/internal/asym"
)

func TestCertificatePEMEscapesVerificationDiagnostics(t *testing.T) {
	t.Parallel()
	info := &asym.CertInfo{RawDER: testcmd.NewTLSCertificateChain(t).Certificate[0], VerifyError: "bad\x1b[2J\r\nname"}
	var output, diagnostics bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&output)
	command.SetErr(&diagnostics)
	require.NoError(t, formatCertificates(command, &asym.PEMFormatter{}, []*asym.CertInfo{info}))
	assert.Equal(t, "certificate verification: not verified: bad\\x1b[2J\\r\\nname\n", diagnostics.String())
	block, rest := pem.Decode(output.Bytes())
	require.NotNil(t, block, "PEM certificate changed")
	assert.Equal(t, info.RawDER, block.Bytes, "PEM certificate changed")
	assert.Empty(t, strings.TrimSpace(string(rest)), "PEM certificate changed")
}

var (
	errKeyTestReadFailed = errors.New("read failed")
	errTestWriteFailed   = errors.New("write failed")
)

func TestReadAndWriteKeyBytesPreserveIOErrors(t *testing.T) {
	t.Parallel()
	readCommand := &cobra.Command{}
	readCommand.SetIn(keyFailingReader{err: errKeyTestReadFailed})
	_, err := readKey(readCommand)
	require.ErrorIs(t, err, errKeyTestReadFailed)

	writeCommand := &cobra.Command{}
	writeCommand.SetOut(keyFailingWriter{err: errTestWriteFailed})
	require.ErrorIs(t, writeKeyBytes(writeCommand, []byte("key"), "test key"), errTestWriteFailed)
}

type keyFailingReader struct{ err error }

func (reader keyFailingReader) Read([]byte) (int, error) { return 0, reader.err }

type keyFailingWriter struct{ err error }

func (writer keyFailingWriter) Write([]byte) (int, error) { return 0, writer.err }
