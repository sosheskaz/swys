package net_test

import (
	"bytes"
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/certinput"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/tlsconfig"
	netcmd "github.com/sosheskaz-systems/npc/cmd/internal/commands/net"
	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
)

var (
	errInvalidNetworkFlags      = netcmd.ErrInvalidFlags
	errInvalidHostPort          = commandio.ErrInvalidHostPort
	errTLSClientKeyMismatch     = tlsconfig.ErrClientKeyMismatch
	errCertificatePathCollision = certinput.ErrPathCollision
	errTrailingCertificateData  = certinput.ErrTrailingData
	errTLSServerKeyMismatch     = netcmd.ErrServerKeyMismatch
)

const (
	netProtocolTCP = "tcp"
	netProtocolUDP = "udp"
	netProtocolTLS = "tls"
)

func newRootCmd() *cobra.Command { return cmd.NewCommand() }

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

func newTLSCertificateChain(t *testing.T) tls.Certificate {
	t.Helper()
	return testcmd.NewTLSCertificateChain(t)
}

func newChainTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	return testcmd.NewChainTLSServer(t)
}

func newNetCmd() *cobra.Command {
	root := newRootCmd()
	for _, command := range root.Commands() {
		if command.Name() == "net" {
			return command
		}
	}
	panic("net command missing from root")
}

func executeRootStreams(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	return executeRootCommandStreams(t, newRootCmd(), args...)
}

func executeRootCommandStreams(t *testing.T, root *cobra.Command, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	err := commandio.Execute(root)
	return stdout.String(), stderr.String(), err
}
