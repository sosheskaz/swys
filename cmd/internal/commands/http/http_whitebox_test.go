package http

import (
	"crypto/tls"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

func TestHTTPDefaultURLScheme(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ input, want string }{
		{"example.com", "https://example.com"},
		{"localhost:8443/path?q=one", "https://localhost:8443/path?q=one"},
		{"[::1]:8443/path", "https://[::1]:8443/path"},
		{"//example.com/path", "https://example.com/path"},
		{"example.com/?next=http://other.test", "https://example.com/?next=http://other.test"},
		{"http://example.com", "http://example.com"},
		{"https://example.com", "https://example.com"},
	} {
		t.Run(test.input, func(t *testing.T) {
			t.Parallel()
			command := newHTTPCmd()
			command.Flags().AddFlagSet(command.PersistentFlags())
			_, address, err := httpMethodURL(command, []string{test.input})
			require.NoError(t, err)
			require.Equal(t, test.want, address.String())
		})
	}
	for _, input := range []string{"", "/path", "http://", "ftp://example.com", "localhost:bad", "http:/example.com", "https:/example.com"} {
		t.Run("invalid/"+input, func(t *testing.T) {
			t.Parallel()
			command := newHTTPCmd()
			command.Flags().AddFlagSet(command.PersistentFlags())
			if _, _, err := httpMethodURL(command, []string{input}); err == nil {
				t.Fatalf("invalid URL %q accepted", input)
			}
		})
	}
}

func newHTTPCmd() *cobra.Command { return NewCommand(commandio.NewLifecycle()) }

func newTLSCertificateChain(t *testing.T) tls.Certificate {
	t.Helper()
	return testcmd.NewTLSCertificateChain(t)
}
