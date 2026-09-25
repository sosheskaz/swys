package cmd

import (
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var outputModeCompletions = []string{
	cobra.CompletionWithDesc("0600", "owner read/write"),
	cobra.CompletionWithDesc("0640", "owner read/write and group read"),
	cobra.CompletionWithDesc("0644", "owner read/write and group/world read"),
}

func registerSharedCompletions(root *cobra.Command) {
	root.InitDefaultCompletionCmd()
	root.InitDefaultHelpCmd()
	registerCommandCompletions(root)
}

func registerCommandCompletions(command *cobra.Command) {
	command.InitDefaultHelpFlag()
	command.InitDefaultVersionFlag()
	command.Flags().VisitAll(func(flag *pflag.Flag) {
		if _, registered := command.GetFlagCompletionFunc(flag.Name); registered {
			return
		}
		switch {
		case flag.Name == "mode":
			mustRegisterSharedFlagCompletion(command, flag.Name, func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
				return filterDescribedCompletions(outputModeCompletions, toComplete), cobra.ShellCompDirectiveNoFileComp
			})
		case flag.Value.Type() == "bool":
			mustRegisterSharedFlagCompletion(command, flag.Name, func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
				return filterDescribedCompletions([]string{strconv.FormatBool(true), strconv.FormatBool(false)}, toComplete), cobra.ShellCompDirectiveNoFileComp
			})
		}
	})
	for _, child := range command.Commands() {
		registerCommandCompletions(child)
	}
}

func mustRegisterSharedFlagCompletion(command *cobra.Command, name string, completion cobra.CompletionFunc) {
	if err := command.RegisterFlagCompletionFunc(name, completion); err != nil {
		panic(err)
	}
}

func filterDescribedCompletions(values []string, prefix string) []string {
	matches := make([]string, 0, len(values))
	for _, value := range values {
		candidate, _, _ := strings.Cut(value, "\t")
		if strings.HasPrefix(candidate, prefix) {
			matches = append(matches, value)
		}
	}
	return matches
}
