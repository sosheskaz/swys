package http_test

import (
	"context"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	httpcmd "github.com/sosheskaz/swys/cmd/internal/commands/http"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

func newRootCmd() *cobra.Command { return cmd.NewCommand() }

var errInvalidHTTPFlags = httpcmd.ErrInvalidFlags

const (
	httpCommandName = httpcmd.TestCommandName
	httpFormatText  = httpcmd.TestFormatText
	httpFormatJSON  = httpcmd.TestFormatJSON
	httpEncodingRaw = httpcmd.TestEncodingRaw
	httpStdinNever  = httpcmd.TestStdinNever
	httpStdinAlways = httpcmd.TestStdinAlways
)

type networkTestIdentity struct {
	caCert, serverCert, serverKey, clientCert, clientKey string
}

func createNetworkTestIdentity(t *testing.T) networkTestIdentity {
	t.Helper()
	identity := testcmd.CreateNetworkIdentity(t, cmd.NewCommand)
	return networkTestIdentity{
		caCert: identity.CACert, serverCert: identity.ServerCert, serverKey: identity.ServerKey,
		clientCert: identity.ClientCert, clientKey: identity.ClientKey,
	}
}

func generateTestKey(t *testing.T, algorithm, path string) {
	t.Helper()
	_, _, err := executeRootStreams(t, "cert", "keygen", "--algorithm", algorithm, "--output", path)
	require.NoError(t, err, "generate %s key: %v", algorithm, err)
}

func executeCommand(root *cobra.Command) error { return commandio.Execute(root) }

func executeRootStreams(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	stdout, stderr, err := testcmd.RunStreams(t, newRootCmd(), nil, args...)
	return string(stdout), string(stderr), err
}

func executeRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	stdout, stderr, err := executeRootStreams(t, args...)
	return stdout + stderr, err
}

func startCancellableHTTPRequest(t *testing.T, server *httptest.Server, input io.Reader, args ...string) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	root := newRootCmd()
	root.SetContext(ctx)
	root.SetIn(input)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs(args)
	done := make(chan error, 1)
	stopped := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		if closer, ok := input.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				t.Errorf("close HTTP test input: %v", err)
			}
		}
		server.CloseClientConnections()
		select {
		case <-stopped:
		case <-time.After(2 * time.Second):
			t.Error("HTTP command worker did not stop during cleanup")
		}
	})
	go func() {
		defer close(stopped)
		done <- executeCommand(root)
	}()
	return cancel, done
}
