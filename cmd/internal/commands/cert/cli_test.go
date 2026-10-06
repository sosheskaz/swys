package cert_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	rootcmd "github.com/sosheskaz/swys/cmd"
	"github.com/sosheskaz/swys/cmd/internal/cli/certinput"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/commands/cert"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

const certificatePEMType = certinput.PEMType

var (
	errCertificateInputSelection  = cert.ErrCertificateInputSelection
	errCertificatePathCollision   = certinput.ErrPathCollision
	errCertificateReportNegative  = cert.ErrCertificateReportNegative
	errTrailingCertificateData    = certinput.ErrTrailingData
	errUnexpectedPEMType          = certinput.ErrUnexpectedPEMType
	errOutputModeUnsupported      = commandio.ErrOutputModeUnsupported
	errUnknownKeyConversionTarget = cert.ErrUnknownKeyConversionTarget
	errUnknownKeyFormat           = cert.ErrUnknownKeyFormat
)

func newRootCmd() *cobra.Command { return rootcmd.NewCommand() }

func certCommand(t *testing.T, path ...string) *cobra.Command {
	t.Helper()
	command, _, err := rootcmd.NewCommand().Find(append([]string{"cert"}, path...))
	require.NoError(t, err)
	return command
}

func executeRootStreams(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	stdout, stderr, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, args...)
	return string(stdout), string(stderr), err
}

func executeRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	stdout, stderr, err := executeRootStreams(t, args...)
	return stdout + stderr, err
}

func executeRootStreamsWithInput(t *testing.T, input io.Reader, args ...string) (string, string, error) {
	t.Helper()
	stdout, stderr, err := testcmd.RunStreams(t, rootcmd.NewCommand(), input, args...)
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

func keyLeaf(t *testing.T, name string) *cobra.Command {
	t.Helper()
	command, _, err := rootcmd.NewCommand().Find([]string{"cert", "key-" + name})
	require.NoError(t, err)
	require.Equal(t, "key-"+name, command.Name())
	return command
}

func executeCommand(root *cobra.Command) error { return commandio.Execute(root) }
