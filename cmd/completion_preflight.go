package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

func prepareQuietCompletion(command *cobra.Command, args []string) bool {
	if (command.Name() != cobra.ShellCompRequestCmd && command.Name() != cobra.ShellCompNoDescRequestCmd) || len(args) == 0 {
		return false
	}
	if completionFlagsParse(args) {
		return false
	}
	// Cobra reports parse errors with the completed arguments to OS stderr and
	// its debug file. Bypass that emitter without changing successful requests.
	run := command.RunE
	command.RunE = func(cmd *cobra.Command, _ []string) error {
		defer func() { command.RunE = run }()
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), ":%d\n", cobra.ShellCompDirectiveNoFileComp); err != nil {
			return fmt.Errorf("write quiet completion directive: %w", err)
		}
		return nil
	}
	return true
}

func completionFlagsParse(args []string) bool {
	probe := NewCommand()
	probe.SetOut(io.Discard)
	probe.SetErr(io.Discard)
	target, completed, err := probe.Find(args[:len(args)-1])
	if err != nil {
		return false
	}
	completed, unknownFlag := completionParseArgs(target, completed, args[len(args)-1])
	if target.ParseFlags(completed) != nil {
		return false
	}
	if !unknownFlag {
		return true
	}
	// Pinned Cobra ignores unknown completion flags after a literal --.
	// This extra parse is confined to the disposable tree, never live values.
	argCount := target.Flags().NArg()
	if target.ParseFlags(append(append([]string(nil), completed...), "--")) != nil {
		return false
	}
	return target.Flags().NArg() > argCount
}

// Match Cobra 1.10.2's checkIfFlagCompletion pending-value normalization.
func completionParseArgs(command *cobra.Command, args []string, current string) ([]string, bool) {
	if command.DisableFlagParsing {
		return args, false
	}
	name := ""
	equals := false
	trimmed := args
	if strings.HasPrefix(current, "-") {
		index := strings.IndexByte(current, '=')
		if index < 0 {
			return args, false
		}
		equals = true
		if strings.HasPrefix(current, "--") {
			name = current[2:index]
		} else {
			name = current[index-1 : index]
		}
	}
	if name == "" && len(args) > 0 {
		name = pendingCompletionFlagName(args[len(args)-1])
		if name != "" {
			trimmed = args[:len(args)-1]
		}
	}
	if name == "" {
		return trimmed, false
	}
	if len(name) == 1 {
		flag := command.Flags().ShorthandLookup(name)
		if flag == nil {
			flag = command.InheritedFlags().ShorthandLookup(name)
		}
		if flag == nil {
			return args, true
		}
		name = flag.Name
	}
	flag := command.Flag(name)
	if flag == nil {
		return args, true
	}
	if !equals && flag.NoOptDefVal != "" {
		return args, false
	}
	return trimmed, false
}

func pendingCompletionFlagName(argument string) string {
	if strings.Contains(argument, "=") {
		return ""
	}
	if len(argument) >= 3 && strings.HasPrefix(argument, "--") {
		return argument[2:]
	}
	if len(argument) >= 2 && argument[0] == '-' && argument[1] != '-' {
		return argument[len(argument)-1:]
	}
	return ""
}
