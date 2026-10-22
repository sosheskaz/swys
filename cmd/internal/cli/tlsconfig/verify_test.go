package tlsconfig_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/cli/tlsconfig"
)

func TestVerifyPeer(t *testing.T) {
	t.Parallel()
	// httptest's self-signed certificate names 127.0.0.1 and example.com.
	server := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	dialer := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
	connection, err := dialer.DialContext(t.Context(), "tcp", server.Listener.Addr().String())
	require.NoError(t, err)
	tlsConnection, ok := connection.(*tls.Conn)
	require.True(t, ok, "TLS dialer returned %T", connection)
	state := tlsConnection.ConnectionState()
	require.NoError(t, connection.Close())
	trusted := x509.NewCertPool()
	trusted.AddCert(server.Certificate())

	for _, test := range []struct {
		wantErr    any
		roots      *x509.CertPool
		name       string
		serverName string
	}{
		// ConnectionState.ServerName is empty here because SNI never carries an IP address.
		{name: "IP address SAN", roots: trusted, serverName: "127.0.0.1"},
		{name: "DNS SAN", roots: trusted, serverName: "example.com"},
		{name: "wrong name", roots: trusted, serverName: "wrong.example.test", wantErr: &x509.HostnameError{}},
		{name: "untrusted root", roots: x509.NewCertPool(), serverName: "127.0.0.1", wantErr: &x509.UnknownAuthorityError{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			chains, err := tlsconfig.VerifyPeer(&state, test.roots, test.serverName)
			if test.wantErr == nil {
				require.NoError(t, err)
				assert.NotEmpty(t, chains)
				return
			}
			require.ErrorAs(t, err, test.wantErr)
			assert.Empty(t, chains)
		})
	}

	_, err = tlsconfig.VerifyPeer(&tls.ConnectionState{}, trusted, "127.0.0.1")
	require.ErrorIs(t, err, tlsconfig.ErrNoPeerCertificates)
}
