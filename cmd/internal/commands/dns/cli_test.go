package dns_test

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"

	rootcmd "github.com/sosheskaz/swys/cmd"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	dnscommand "github.com/sosheskaz/swys/cmd/internal/commands/dns"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
	"github.com/sosheskaz/swys/internal/dnsquery"
)

var (
	errInvalidDNSOptions   = dnscommand.ErrInvalidDNSOptions
	errDNSResponseMismatch = dnsquery.ErrResponseMismatch
)

type dnsJSONDocument struct {
	Results []dnsquery.Result `json:"results"`
	Values  []string          `json:"values"`
}

func newRootCmd() *cobra.Command { return rootcmd.NewCommand() }
func newRootCmdWithDNSDependencies(deps dnsquery.Dependencies) *cobra.Command {
	return testcmd.NewDNSRoot(deps)
}

func newDNSCmd(deps dnsquery.Dependencies) *cobra.Command {
	return dnscommand.NewCommand(commandio.NewLifecycle(), deps)
}

func defaultDNSDependencies() dnsquery.Dependencies { return dnsquery.DefaultDependencies() }
func directDNSRecordTypes() []string                { return dnscommand.DirectRecordTypesForTest() }

func executeRootStreams(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	stdout, stderr, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, args...)
	return string(stdout), string(stderr), err
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

func closeCommandIO(command *cobra.Command) error { return commandio.Close(command) }
