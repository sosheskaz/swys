package http_test

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/cmd"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	httpcmd "github.com/sosheskaz-systems/npc/cmd/internal/commands/http"
	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
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
