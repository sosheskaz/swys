package commandio

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var errUnsupportedIOFlag = errors.New("unsupported I/O flag")

var mainIOFlags = [...]string{"input", "output", "mode"}

// SupportsFlag reports a leaf's operational I/O support or a branch's child union.
func (lifecycle *Lifecycle) SupportsFlag(command *cobra.Command, name string) bool {
	if command.HasSubCommands() {
		for _, child := range command.Commands() {
			if child.IsAvailableCommand() && lifecycle.SupportsFlag(child, name) {
				return true
			}
		}
		return false
	}
	behavior, registered := lifecycle.Behavior(command)
	if !registered {
		return true
	}
	switch name {
	case "input":
		return behavior.SupportsInput
	case "output", "mode":
		return behavior.SupportsOutput
	default:
		return true
	}
}

func (lifecycle *Lifecycle) validateIOCapabilities(command *cobra.Command) error {
	for _, name := range mainIOFlags {
		if flag := command.Flag(name); flag != nil && flag.Changed && !lifecycle.SupportsFlag(command, name) {
			return fmt.Errorf("%w: --%s for %s", errUnsupportedIOFlag, name, command.CommandPath())
		}
	}
	return nil
}

// ReferenceHelp presents only operational I/O flags supported by command.
func (lifecycle *Lifecycle) ReferenceHelp(command *cobra.Command, render func()) {
	restore := snapshotIOFlagVisibility(command)
	defer restore()
	lifecycle.hideUnsupportedIOFlags(command)
	render()
}

func (lifecycle *Lifecycle) hideUnsupportedIOFlags(command *cobra.Command) {
	for _, name := range mainIOFlags {
		if flag := command.Flag(name); flag != nil && !lifecycle.SupportsFlag(command, name) {
			flag.Hidden = true
		}
	}
}

func snapshotIOFlagVisibility(command *cobra.Command) func() {
	type visibility struct {
		flag   *pflag.Flag
		hidden bool
	}
	var flags []visibility
	for _, name := range mainIOFlags {
		if flag := command.Flag(name); flag != nil {
			flags = append(flags, visibility{flag: flag, hidden: flag.Hidden})
		}
	}
	return func() {
		for _, state := range flags {
			state.flag.Hidden = state.hidden
		}
	}
}

func (lifecycle *Lifecycle) prepareShellCompletion(command *cobra.Command, args []string) bool {
	if command.Name() != cobra.ShellCompRequestCmd && command.Name() != cobra.ShellCompNoDescRequestCmd {
		return false
	}
	restore := snapshotIOFlagVisibility(command)
	lifecycle.PrepareCompletion(command, args)
	if len(args) > 0 {
		if target, _, err := command.Root().Find(args[:len(args)-1]); err == nil {
			lifecycle.hideUnsupportedIOFlags(target)
		}
	}
	// Cobra's internal completion command runs after the pre-run hook and parses
	// its target's flags there. Keep shared flag visibility scoped to that run.
	run := command.Run
	command.Run = func(cmd *cobra.Command, args []string) {
		defer func() {
			restore()
			command.Run = run
		}()
		run(cmd, args)
	}
	return true
}
