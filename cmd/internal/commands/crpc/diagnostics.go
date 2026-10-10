package crpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"slices"
	"strings"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/sosheskaz/swys/internal/textdisplay"
)

type diagnosticError struct{ cause error }

func (err *diagnosticError) Error() string { return textdisplay.Escape(err.cause.Error()) }
func (err *diagnosticError) Unwrap() error { return err.cause }

func safeError(err error) error {
	if err == nil {
		return nil
	}
	return &diagnosticError{cause: err}
}

func writeDiagnostics(ctx context.Context, output io.Writer, call *connect.CallInfo, callErr error) error {
	var buffer strings.Builder
	status := "OK"
	if callErr != nil {
		status = textdisplay.Escape(callErr.Error())
	}
	fmt.Fprintf(&buffer, "Connect status: %s\n", status)
	if info, exists := connecthttp.ClientInfoForContext(ctx); exists {
		fmt.Fprintf(&buffer, "Connect transport: %s", textdisplay.Escape(info.ResponseProto()))
		if state := info.TLS(); state != nil {
			fmt.Fprintf(&buffer, "; %s; cipher=%s; server name=%s; verified=%t",
				tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite),
				textdisplay.Escape(state.ServerName), len(state.VerifiedChains) > 0)
		}
		buffer.WriteByte('\n')
	}
	for _, section := range []struct {
		header *connect.Header
		name   string
	}{
		{call.ResponseHeader(), "header"}, {call.ResponseTrailer(), "trailer"},
	} {
		var names []string
		for name := range section.header.All() {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			for _, value := range section.header.Values(name) {
				fmt.Fprintf(&buffer, "Connect %s: %s: %s\n", section.name, textdisplay.Escape(name), textdisplay.Escape(value))
			}
		}
	}
	if _, err := io.WriteString(output, buffer.String()); err != nil {
		return fmt.Errorf("write Connect diagnostics: %w", err)
	}
	return nil
}
