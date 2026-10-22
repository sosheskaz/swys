package net_test

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	netcmd "github.com/sosheskaz/swys/cmd/internal/commands/net"
	"github.com/sosheskaz/swys/internal/netconn"
)

func TestExampleNetConnectResolvesTCPEndpoint(t *testing.T) {
	t.Parallel()
	requestPath := filepath.Join(t.TempDir(), "request")
	require.NoError(t, os.WriteFile(requestPath, []byte("status\n"), 0o600))
	address, serverResult := startEOFResponseServer(t, "status\n", "ok\n")
	endpoint := endpointWithHost(t, address, "service.test")

	stdout, stderr, err := executeRootStreams(t, "net", "connect", endpoint,
		"--resolve", endpoint+":127.0.0.1", "--input", requestPath)
	require.NoError(t, err)
	assert.Equal(t, "ok\n", stdout)
	assert.Empty(t, stderr)
	if result := <-serverResult; result.err != nil || result.request != "status\n" {
		t.Fatalf("server result = %+v", result)
	}
}

func TestExampleNetConnectResolveKeepsTLSServerName(t *testing.T) {
	t.Parallel()
	serverNames := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{newTLSCertificateChain(t)},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			serverNames <- hello.ServerName
			return nil, nil //nolint:nilnil // nil directs TLS to continue with the existing configuration
		},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	endpoint := endpointWithHost(t, server.Listener.Addr().String(), "service.test")

	_, _, err := executeRootStreamsWithInput(t, strings.NewReader(""), "net", "connect", "--tls", "--insecure",
		"--resolve", endpoint+":127.0.0.1", endpoint)
	require.NoError(t, err)
	select {
	case got := <-serverNames:
		assert.Equal(t, "service.test", got, "SNI names the requested host, not the override address")
	case <-time.After(time.Second):
		t.Fatal("server did not receive ClientHello")
	}
}

func TestExampleNetConnectResolvesUDPEndpoint(t *testing.T) {
	t.Parallel()
	address, result := startExampleUDPServer(t, []byte("pong"))
	endpoint := endpointWithHost(t, address, "service.test")

	stdout, _, err := executeRootStreamsWithInput(t, strings.NewReader("ping"),
		"net", "connect", "--udp", endpoint, "--resolve", endpoint+":127.0.0.1", "--wait", "1s")
	require.NoError(t, err)
	assert.Equal(t, "pong", stdout)
	if got := <-result; got.err != nil || got.request != "ping" {
		t.Fatalf("server result = %+v", got)
	}
}

func TestNetConnectResolveValidatesBeforeIO(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		want error
		name string
		args []string
	}{
		{name: "malformed rule", args: []string{"net", "connect", "service.test:443", "--resolve", "service.test:443"}, want: netconn.ErrInvalidResolve},
		{name: "hostname address", args: []string{"net", "connect", "service.test:443", "--resolve", "service.test:443:localhost"}, want: netconn.ErrInvalidResolve},
		{
			name: "UDP fallback addresses", args: []string{"net", "connect", "--udp", "service.test:53", "--resolve", "service.test:53:192.0.2.1,192.0.2.2"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output := filepath.Join(t.TempDir(), "output")
			require.NoError(t, os.WriteFile(output, []byte("preserve"), 0o600))
			_, _, err := executeRootStreamsWithInput(t, strings.NewReader("request"), append(test.args, "--output", output)...)
			require.ErrorIs(t, err, netcmd.ErrInvalidFlags)
			if test.want != nil {
				require.ErrorIs(t, err, test.want)
			}
			contents, readErr := os.ReadFile(output)
			require.NoError(t, readErr)
			assert.Equal(t, "preserve", string(contents))
		})
	}
}

func endpointWithHost(t *testing.T, address, host string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	require.NoError(t, err)
	return net.JoinHostPort(host, port)
}
