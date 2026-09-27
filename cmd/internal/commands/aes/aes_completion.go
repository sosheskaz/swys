package aes

import (
	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
)

func registerAESNoFileFlagCompletion(cmd *cobra.Command, name string) {
	if err := cmd.RegisterFlagCompletionFunc(name, func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		panic(err)
	}
}

// prepareAESCompletion hides flags incompatible with the selected wire format.
func prepareAESCompletion(completionCmd *cobra.Command, args []string) {
	if (completionCmd.Name() != cobra.ShellCompRequestCmd && completionCmd.Name() != cobra.ShellCompNoDescRequestCmd) || len(args) == 0 {
		return
	}
	probe := commandio.NewProbeRoot()
	probe.AddCommand(NewCommand(commandio.NewLifecycle()))
	parsed, remaining, err := probe.Find(args[:len(args)-1])
	if err != nil || !isAESOperation(parsed) {
		return
	}
	if err := parsed.ParseFlags(remaining); err != nil {
		return
	}
	actual, _, err := completionCmd.Root().Find(args[:len(args)-1])
	if err != nil || !isAESOperation(actual) {
		return
	}
	wire, err := getAESString(parsed, "wire-format")
	if err != nil {
		return
	}
	if wire == wireOpenPGP {
		for _, name := range []string{"aad", flagHKDFHash, flagDerivedBits} {
			actual.Flags().Lookup(name).Hidden = true
		}
	}
	if wire == wireTink {
		actual.Flags().Lookup("key-id").Hidden = true
	}
}

func isAESOperation(cmd *cobra.Command) bool {
	return cmd != nil && cmd.Parent() != nil && cmd.Parent().Name() == "aes" &&
		(cmd.Name() == "encrypt" || cmd.Name() == commandDecrypt)
}
