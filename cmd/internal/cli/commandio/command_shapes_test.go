package commandio

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestNetworkCommandPanicsWhenWrappedCommandUsesRunInsteadOfRunE(t *testing.T) {
	t.Parallel()
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("networkCommand did not panic on a command with Run instead of RunE")
		}
		message, ok := recovered.(string)
		if !ok || !strings.Contains(message, "RunE") {
			t.Fatalf("panic value = %v, want a message naming the missing RunE", recovered)
		}
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
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "plain text" {
		t.Fatalf("input = %q, want %q", data, "plain text")
	}
}

func TestOutputModeIsRejectedOnWindows(t *testing.T) {
	t.Parallel()
	command := &cobra.Command{Use: "mode-test"}
	command.Flags().String("mode", "", "")
	require.NoError(t, command.Flags().Set("mode", "0640"))

	_, err := commandOutputOptionsWithBehavior(command, nil, "windows")
	if !errors.Is(err, ErrOutputModeUnsupported) {
		t.Fatalf("error = %v, want unsupported-output-mode", err)
	}
}

func TestSharedCompletionAcceptsValidManualMode(t *testing.T) {
	t.Parallel()
	if _, err := parseOutputMode("0750"); err != nil {
		t.Fatalf("valid manual mode rejected: %v", err)
	}
}
