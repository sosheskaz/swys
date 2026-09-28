package commandio

import (
	"io"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkCommandPanicsWhenWrappedCommandUsesRunInsteadOfRunE(t *testing.T) {
	t.Parallel()
	defer func() {
		recovered := recover()
		require.NotNil(t, recovered, "networkCommand did not panic on a command with Run instead of RunE")
		message, ok := recovered.(string)
		require.True(t, ok, "panic type = %T, want string", recovered)
		require.Contains(t, message, "RunE")
	}()

	NetworkCommand(&cobra.Command{
		Use: "network-run-test host:port",
		Run: func(*cobra.Command, []string) {},
	})
}

func TestCommandInputTreatsMissingInputEncodingFlagAsRaw(t *testing.T) {
	t.Parallel()
	command := &cobra.Command{Use: "no-input-encoding-test"}
	input, err := CommandInput(command, []string{"plain", "text"})
	require.NoError(t, err)
	data, err := io.ReadAll(input)
	require.NoError(t, err)
	assert.Equal(t, "plain text", string(data))
}

func TestOutputModeIsRejectedOnWindows(t *testing.T) {
	t.Parallel()
	command := &cobra.Command{Use: "mode-test"}
	command.Flags().String("mode", "", "")
	require.NoError(t, command.Flags().Set("mode", "0640"))

	_, err := commandOutputOptionsWithBehavior(command, nil, "windows")
	assert.ErrorIs(t, err, ErrOutputModeUnsupported)
}

func TestSharedCompletionAcceptsValidManualMode(t *testing.T) {
	t.Parallel()
	_, err := parseOutputMode("0750")
	assert.NoError(t, err)
}
