package cmd

import (
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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

	networkCommand(&cobra.Command{
		Use: "network-run-test host:port",
		Run: func(*cobra.Command, []string) {},
	})
}

func TestCommandInputTreatsMissingInputEncodingFlagAsRaw(t *testing.T) {
	t.Parallel()
	command := &cobra.Command{Use: "no-input-encoding-test"}
	input, err := commandInput(command, []string{"plain", "text"})
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
