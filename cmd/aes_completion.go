package cmd

import "github.com/spf13/cobra"

func completeAESCipherModes(cmd *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	aadSelected := cmd.Flags().Changed("aad")
	ivFlag := cmd.Flags().Lookup("iv")
	ivSelected := ivFlag != nil && ivFlag.Changed
	chunkSelected := cmd.Flags().Changed("chunk-size")
	rawSelected := cmd.Flags().Changed("raw")

	completions := make([]string, 0, len(aesCipherModes))
	for _, name := range aesCipherModeNames() {
		mode := aesCipherModes[name]
		if (aadSelected && mode != aesCipherModeGCM) || (ivSelected && mode != aesCipherModeCBC) || ((chunkSelected || rawSelected) && mode != aesCipherModeGCM) {
			continue
		}
		completions = append(completions, cobra.CompletionWithDesc(name, aesCipherModeDescriptions[mode]))
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func registerAESNoFileFlagCompletion(cmd *cobra.Command, name string) {
	if err := cmd.RegisterFlagCompletionFunc(name, func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		panic(err)
	}
}

// prepareAESCompletion hides flags that conflict with the selected cipher mode
// before Cobra enumerates flag-name completions. It only mutates the fresh
// command tree serving an internal completion request.
func prepareAESCompletion(completionCmd *cobra.Command, args []string) {
	if (completionCmd.Name() != cobra.ShellCompRequestCmd && completionCmd.Name() != cobra.ShellCompNoDescRequestCmd) || len(args) == 0 {
		return
	}

	completedArgs := args[:len(args)-1]
	mode, aadSelected, ivSelected, ok := probeAESCompletion(completedArgs)
	if !ok {
		return
	}
	actualCommand, _, err := completionCmd.Root().Find(completedArgs)
	if err != nil || !isAESOperation(actualCommand) {
		return
	}
	if mode == aesCipherModeCBC || ivSelected {
		actualCommand.Flags().Lookup("aad").Hidden = true
		actualCommand.Flags().Lookup("raw").Hidden = true
		if chunk := actualCommand.Flags().Lookup("chunk-size"); chunk != nil {
			chunk.Hidden = true
		}
	}
	if mode == aesCipherModeGCM || aadSelected {
		if actualIV := actualCommand.Flags().Lookup("iv"); actualIV != nil {
			actualIV.Hidden = true
		}
	}
}

func probeAESCompletion(args []string) (aesCipherMode, bool, bool, bool) {
	probeCommand, probeArgs, err := newRootCmd().Find(args)
	if err != nil || !isAESOperation(probeCommand) {
		return "", false, false, false
	}
	if err := probeCommand.ParseFlags(probeArgs); err != nil {
		return "", false, false, false
	}
	mode, err := aesCipherModeFromCommand(probeCommand)
	if err != nil {
		return "", false, false, false
	}
	ivFlag := probeCommand.Flags().Lookup("iv")
	ivSelected := ivFlag != nil && ivFlag.Changed
	return mode, probeCommand.Flags().Changed("aad"), ivSelected, true
}

func isAESOperation(cmd *cobra.Command) bool {
	if cmd == nil || cmd.Parent() == nil || cmd.Parent().Name() != "aes" {
		return false
	}
	return cmd.Name() == "encrypt" || cmd.Name() == "decrypt"
}
