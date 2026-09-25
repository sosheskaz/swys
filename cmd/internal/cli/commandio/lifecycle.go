package commandio

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/encoding"
)

// Behavior describes the command-specific work around the shared I/O lifecycle.
// Registration is bound to a Cobra command instance, so a fresh root tree owns
// fresh behavior and prepared state.
type Behavior struct {
	BeforeIO              func(*cobra.Command, []string) (func(error) error, error)
	Validate              func(*cobra.Command) error
	Prepare               func(*cobra.Command, io.Reader) ([]byte, error)
	PrepareInput          func(*cobra.Command) error
	OutputEncoder         func(string) (encoding.OutputEncoder, error)
	Sensitive             func(*cobra.Command) (bool, error)
	PreparesOutput        func(*cobra.Command) bool
	SkipIOIf              func(*cobra.Command, []string) bool
	SkipIO                bool
	InputPrepared         bool
	ClearInheritedStreams bool
}

// Lifecycle binds command-specific behavior to one Cobra command tree.
type Lifecycle struct {
	behaviors   map[*cobra.Command]Behavior
	completions []func(*cobra.Command, []string)
}

// RegisterCompletion adds a callback run before shell completion.
func (lifecycle *Lifecycle) RegisterCompletion(prepare func(*cobra.Command, []string)) {
	lifecycle.completions = append(lifecycle.completions, prepare)
}

// PrepareCompletion runs the tree's registered completion callbacks.
func (lifecycle *Lifecycle) PrepareCompletion(command *cobra.Command, args []string) {
	for _, prepare := range lifecycle.completions {
		prepare(command, args)
	}
}

// NewLifecycle creates behavior storage for a fresh command tree.
func NewLifecycle() *Lifecycle {
	return &Lifecycle{behaviors: make(map[*cobra.Command]Behavior)}
}

// Register associates one command with its validation and I/O preparation.
func (lifecycle *Lifecycle) Register(command *cobra.Command, behavior Behavior) {
	if _, exists := lifecycle.behaviors[command]; exists {
		panic("command I/O behavior already registered")
	}
	lifecycle.behaviors[command] = behavior
}

// Behavior returns the behavior registered for command, if any.
func (lifecycle *Lifecycle) Behavior(command *cobra.Command) (Behavior, bool) {
	behavior, ok := lifecycle.behaviors[command]
	return behavior, ok
}

// PreRun applies the registered command behavior before opening output.
func (lifecycle *Lifecycle) PreRun(command *cobra.Command, args []string) error {
	lifecycle.PrepareCompletion(command, args)
	behavior, registered := lifecycle.Behavior(command)
	if !registered {
		return Configure(command, nil)
	}
	var afterConfigure func(error) error
	if behavior.BeforeIO != nil {
		var err error
		afterConfigure, err = behavior.BeforeIO(command, args)
		if err != nil {
			return err
		}
	}
	if behavior.SkipIO || behavior.SkipIOIf != nil && behavior.SkipIOIf(command, args) {
		if afterConfigure != nil {
			return afterConfigure(nil)
		}
		return nil
	}
	err := Configure(command, &behavior)
	if afterConfigure != nil {
		return afterConfigure(err)
	}
	return err
}
