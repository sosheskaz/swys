// Package presentation resolves human-output policy before command streams change.
package presentation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/sosheskaz/swys/internal/textdisplay"
)

// ErrStyle identifies an unsupported presentation policy.
var ErrStyle = errors.New("invalid presentation style")

// Auto, Rich, and Plain are the supported human-output policies.
const (
	Auto  = "auto"
	Rich  = "rich"
	Plain = "plain"
)

// Dependencies allows deterministic terminal and environment inspection.
type Dependencies struct {
	Terminal func(io.Writer) (bool, int)
	Getenv   func(string) (string, bool)
}

type (
	dependenciesKey struct{}
	optionsKey      struct{}
)

type streams struct {
	out textdisplay.Options
	err textdisplay.Options
}

// WithDependencies supplies presentation hooks on a command's context.
func WithDependencies(ctx context.Context, dependencies Dependencies) context.Context {
	return context.WithValue(ctx, dependenciesKey{}, dependencies)
}

// Terminal reports the actual terminal size of a writer.
func Terminal(writer io.Writer) (bool, int) {
	file, ok := writer.(interface{ Fd() uintptr })
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return false, 0
	}
	width, _, err := term.GetSize(int(file.Fd()))
	if err != nil {
		return true, 0
	}
	return true, width
}

// AddFlags installs the shared presentation override.
func AddFlags(root *cobra.Command) {
	root.PersistentFlags().String("style", Auto, "human text styling (auto, rich, plain)")
	if err := root.RegisterFlagCompletionFunc("style", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{Auto, Rich, Plain}, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		panic(err)
	}
}

// Resolve validates policy and captures both original streams before I/O setup.
// The returned restore function must run after the command's I/O cleanup.
func Resolve(command *cobra.Command) (func(), error) {
	style, err := Policy(command)
	if err != nil {
		return nil, err
	}
	original := command.Context()
	dependencies := commandDependencies(original)
	options := streams{
		out: resolveStream(command.OutOrStdout(), style, dependencies),
		err: resolveStream(command.ErrOrStderr(), style, dependencies),
	}
	if redirected(command) {
		if style == Auto {
			options.out.Rich = false
		}
		options.out.Width = 100
	}
	command.SetContext(context.WithValue(original, optionsKey{}, options))
	return func() { command.SetContext(original) }, nil
}

func resolveStream(writer io.Writer, style string, dependencies Dependencies) textdisplay.Options {
	terminal, width := dependencies.Terminal(writer)
	if !terminal || width <= 0 {
		width = 100
	}
	options := textdisplay.Options{Width: width}
	noColor, _ := dependencies.Getenv("NO_COLOR")
	termName, _ := dependencies.Getenv("TERM")
	options.Rich = style == Rich || style == Auto && terminal && noColor == "" && termName != "dumb"
	return options
}

// Output returns presentation options for the original stdout destination.
func Output(command *cobra.Command) textdisplay.Options {
	if options, ok := command.Context().Value(optionsKey{}).(streams); ok {
		return options.out
	}
	return textdisplay.Options{}
}

// Diagnostics returns presentation options for stderr, independently of stdout.
func Diagnostics(command *cobra.Command) textdisplay.Options {
	if options, ok := command.Context().Value(optionsKey{}).(streams); ok {
		return options.err
	}
	return textdisplay.Options{}
}

func redirected(command *cobra.Command) bool {
	file := command.Flag("output")
	encoded := command.Flag("encoding")
	return file != nil && file.Value.String() != "" && file.Value.String() != "-" ||
		encoded != nil && encoded.Value.String() != "raw"
}

// Policy validates and resolves an explicit format override.
func Policy(command *cobra.Command) (string, error) {
	style := Auto
	if flag := command.Flag("style"); flag != nil {
		style = flag.Value.String()
	}
	if style != Auto && style != Rich && style != Plain {
		return "", fmt.Errorf("%w %q (valid: auto, rich, plain)", ErrStyle, style)
	}
	if flag := command.Flag("format"); flag != nil && flag.Value.String() == Plain {
		style = Plain
	}
	return style, nil
}

func commandDependencies(ctx context.Context) Dependencies {
	dependencies, ok := ctx.Value(dependenciesKey{}).(Dependencies)
	if !ok {
		dependencies = Dependencies{}
	}
	if dependencies.Terminal == nil {
		dependencies.Terminal = Terminal
	}
	if dependencies.Getenv == nil {
		dependencies.Getenv = os.LookupEnv
	}
	return dependencies
}

// WriteError reports a final error, styling only the existing prefix.
func WriteError(command *cobra.Command, failure error) error {
	style, err := Policy(command)
	if err != nil {
		style = Auto
	}
	options := resolveStream(command.ErrOrStderr(), style, commandDependencies(command.Context()))
	prefix := textdisplay.Style("swys:", textdisplay.Failure, options.Rich)
	if _, err := fmt.Fprintf(command.ErrOrStderr(), "%s %v\n", prefix, failure); err != nil {
		return fmt.Errorf("write final error: %w", err)
	}
	return nil
}
