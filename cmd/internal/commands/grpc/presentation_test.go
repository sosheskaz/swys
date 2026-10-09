package grpc

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGRPCDiagnosticsReportShortWrite(t *testing.T) {
	t.Parallel()
	require.ErrorIs(t, writeGRPCDiagnostics(shortDiagnosticWriter{}, &grpcOptions{}, grpcCallDetails{}), io.ErrShortWrite)
}

type shortDiagnosticWriter struct{}

func (shortDiagnosticWriter) Write([]byte) (int, error) { return 0, nil }
