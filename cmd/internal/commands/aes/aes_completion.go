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

// prepareAESCompletion hides flags incompatible with the selected credential
// and wire format.
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
	hideIncompatibleAESFlags(parsed, actual)
}

func hideIncompatibleAESFlags(parsed, actual *cobra.Command) {
	hide := func(names ...string) {
		for _, name := range names {
			if flag := actual.Flags().Lookup(name); flag != nil {
				flag.Hidden = true
			}
		}
	}
	if passwordSelected(parsed) {
		hide("key-format", "key-id", flagAAD, flagHKDFHash, flagDerivedBits)
		return
	}
	hide(kdfMemoryFlag, kdfPassesFlag, kdfParallelismFlag)
	wire, err := getAESString(parsed, "wire-format")
	if err != nil {
		return
	}
	if wire == wireOpenPGP {
		hide(flagAAD, flagHKDFHash, flagDerivedBits)
	}
	if wire == wireTink {
		hide("key-id")
	}
}

func isAESOperation(cmd *cobra.Command) bool {
	return cmd != nil && cmd.Parent() != nil && cmd.Parent().Name() == "aes" &&
		(cmd.Name() == "encrypt" || cmd.Name() == commandDecrypt)
}
