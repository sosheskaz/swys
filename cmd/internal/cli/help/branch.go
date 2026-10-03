package help

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const branchCommandShape = "npc.help.branch"

// ConfigureBranch makes Cobra validate child names before command I/O.
func ConfigureBranch(command *cobra.Command) {
	command.Args = func(command *cobra.Command, args []string) error {
		if len(args) == 0 {
			return pflag.ErrHelp
		}
		return cobra.NoArgs(command, args)
	}
	command.RunE = func(*cobra.Command, []string) error { return nil }
	if command.Annotations == nil {
		command.Annotations = make(map[string]string)
	}
	command.Annotations[branchCommandShape] = commandShapeEnabled
}

func isBranchCommand(command *cobra.Command) bool {
	return command.Annotations[branchCommandShape] == commandShapeEnabled
}

func branchReferenceHelp(command *cobra.Command, render func()) {
	if !isBranchCommand(command) {
		render()
		return
	}
	// Cobra needs a runnable handler for validation, but reference usage should
	// present the branch as a choice of children.
	run, runE := command.Run, command.RunE
	command.Run, command.RunE = nil, nil
	defer func() { command.Run, command.RunE = run, runE }()
	render()
}
