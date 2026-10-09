// Package help renders command reference text and embedded guides.
package help

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/presentation"
)

const (
	guideCommandShape   = "guide"
	commandShapeEnabled = "true"
	defaultGuideWidth   = 80
)

// Dependencies supplies environment, terminal, and process hooks for help.
type Dependencies struct {
	Getenv   func(string) (string, bool)
	Terminal func(io.Writer) (bool, int)
	Command  func(context.Context, string, ...string) *exec.Cmd
}

// DefaultDependencies uses the current process environment and terminal.
func DefaultDependencies() Dependencies {
	return Dependencies{
		Getenv:   os.LookupEnv,
		Terminal: guideTerminal,
		Command:  exec.CommandContext,
	}
}

// WithDefaults fills omitted hooks with their process defaults.
func (dependencies Dependencies) WithDefaults() Dependencies {
	defaults := DefaultDependencies()
	if dependencies.Getenv == nil {
		dependencies.Getenv = defaults.Getenv
	}
	if dependencies.Terminal == nil {
		dependencies.Terminal = defaults.Terminal
	}
	if dependencies.Command == nil {
		dependencies.Command = defaults.Command
	}
	return dependencies
}

// Configure installs help rendering, guide lookup, and paging on root.
func Configure(root *cobra.Command, dependencies Dependencies, referencePresentation func(*cobra.Command, func())) {
	dependencies = dependencies.WithDefaults()
	referenceHelp := root.HelpFunc()
	root.SetHelpFunc(func(command *cobra.Command, args []string) {
		branchReferenceHelp(command, func() {
			if referencePresentation != nil {
				referencePresentation(command, func() { referenceHelp(command, args) })
			} else {
				referenceHelp(command, args)
			}
		})
		key := canonicalGuideKey(root, command)
		if _, ok := guideSource(command); !ok {
			return
		}
		invocation := "swys help"
		if key != "" {
			invocation += " " + key
		}
		if _, err := fmt.Fprintf(command.OutOrStdout(), "\nFor a usage guide, run '%s'.\n", invocation); err != nil {
			command.PrintErrf("write usage-guide pointer: %v\n", err)
		}
	})

	configureGuideCommands(root, root, dependencies)
}

func configureGuideCommands(root, scope *cobra.Command, dependencies Dependencies) {
	for _, child := range scope.Commands() {
		if IsGuideCommand(child) {
			scope.RemoveCommand(child)
			continue
		}
		configureGuideCommands(root, child, dependencies)
	}
	if scope != root && (!scope.HasSubCommands() || (scope.Runnable() && !isBranchCommand(scope))) {
		return
	}
	scope.SetHelpCommand(newGuideCommand(root, scope, dependencies))
	scope.InitDefaultHelpCmd()
}

func newGuideCommand(root, scope *cobra.Command, dependencies Dependencies) *cobra.Command {
	var rich bool
	var plain bool
	var noPager bool

	command := &cobra.Command{
		Use:   "help [command path]",
		Short: "Read a curated guide for a command",
		Long: `Read a curated guide for an swys command.

Paths are relative to the command group containing help. With no path, read
that group's guide. Use a command's --help flag for its arguments and flags.`,
		Args: cobra.ArbitraryArgs,
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
			parent, err := resolveGuideTarget(root, scopedGuidePath(root, scope, args))
			if err != nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			var completions []cobra.Completion
			for _, child := range publicGuideChildren(parent) {
				if strings.HasPrefix(child.Name(), toComplete) || aliasHasPrefix(child, toComplete) {
					completions = append(completions, cobra.CompletionWithDesc(child.Name(), child.Short))
				}
			}
			return completions, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(command *cobra.Command, args []string) error {
			return runGuide(command, root, dependencies, scopedGuidePath(root, scope, args), guideOptions{
				rich: rich, plain: plain, noPager: noPager,
			})
		},
	}
	command.Flags().BoolVar(&rich, "rich", false, "force rendered ANSI presentation")
	command.Flags().BoolVar(&plain, "plain", false, "force plain rendered text")
	command.Flags().BoolVar(&noPager, "no-pager", false, "write directly instead of using PAGER")
	command.MarkFlagsMutuallyExclusive("rich", "plain")
	command.Annotations = map[string]string{guideCommandShape: commandShapeEnabled}
	return command
}

func scopedGuidePath(root, scope *cobra.Command, args []string) []string {
	return append(strings.Fields(canonicalGuideKey(root, scope)), args...)
}

type guideOptions struct {
	style   string
	rich    bool
	plain   bool
	noPager bool
}

func runGuide(
	command *cobra.Command,
	root *cobra.Command,
	dependencies Dependencies,
	path []string,
	options guideOptions,
) error {
	for _, flagName := range []string{"input", "output", "mode"} {
		flag := command.Flags().Lookup(flagName)
		if flag != nil && flag.Changed {
			return fmt.Errorf(
				"%w: --%s; use shell redirection to save a guide",
				ErrGuideOperationalFlag,
				flagName,
			)
		}
	}

	target, err := resolveGuideTarget(root, path)
	if err != nil {
		return err
	}
	key := canonicalGuideKey(root, target)
	source, ok := guideSource(target)
	if !ok {
		reference := "swys --help"
		if key != "" {
			reference = "swys " + key + " --help"
		}
		return fmt.Errorf(
			"%w for %q; run '%s' for reference help",
			errGuideNotFound,
			guideDisplayPath(key),
			reference,
		)
	}

	style, err := presentation.Policy(command)
	if err != nil {
		return err
	}
	options.style = style
	stdout := command.OutOrStdout()
	isTerminal, terminalWidth := dependencies.Terminal(stdout)
	pager, pagerSet := dependencies.Getenv("PAGER")
	usePager := isTerminal && pagerSet && pager != "" && !options.noPager
	rich := guideRichPresentation(dependencies, options, isTerminal, usePager)
	width := guideLayoutWidth(isTerminal, terminalWidth)
	rendered, err := renderGuide(source, guideRenderOptions{rich: rich, width: width})
	if err != nil {
		return fmt.Errorf("render guide for %q: %w", guideDisplayPath(key), err)
	}
	if !usePager {
		if err := writeGuide(stdout, rendered); err != nil {
			return fmt.Errorf("write guide for %q: %w", guideDisplayPath(key), err)
		}
		return nil
	}
	return presentGuideThroughPager(command, dependencies, pager, rendered)
}

func guideRichPresentation(
	dependencies Dependencies,
	options guideOptions,
	isTerminal bool,
	usePager bool,
) bool {
	if options.rich {
		return true
	}
	if options.plain {
		return false
	}
	if options.style == presentation.Rich {
		return true
	}
	if options.style == presentation.Plain {
		return false
	}
	if value, ok := dependencies.Getenv("NO_COLOR"); ok && value != "" {
		return false
	}
	if value, ok := dependencies.Getenv("TERM"); ok && value == "dumb" {
		return false
	}
	return isTerminal && !usePager
}

func guideLayoutWidth(isTerminal bool, terminalWidth int) int {
	if !isTerminal || terminalWidth <= 0 {
		return defaultGuideWidth
	}
	if terminalWidth < defaultGuideWidth {
		return terminalWidth
	}
	return defaultGuideWidth
}

func guideTerminal(writer io.Writer) (bool, int) {
	return presentation.Terminal(writer)
}

func resolveGuideTarget(root *cobra.Command, path []string) (*cobra.Command, error) {
	current := root
	for index, component := range path {
		var match *cobra.Command
		for _, child := range publicGuideChildren(current) {
			if child.Name() != component && !child.HasAlias(component) {
				continue
			}
			if match != nil {
				return nil, fmt.Errorf(
					"%w: ambiguous component %q under %q",
					errGuidePath,
					component,
					guideCommandPath(root, current),
				)
			}
			match = child
		}
		if match != nil {
			current = match
			continue
		}

		parentPath := canonicalGuideKey(root, current)
		parentInvocation := "swys help"
		if parentPath != "" {
			parentInvocation += " " + parentPath
		}
		consumed := strings.Join(path[:index], " ")
		if len(publicGuideChildren(current)) == 0 {
			return nil, fmt.Errorf(
				"%w: unexpected component %q after %q; try '%s'",
				errGuidePath,
				component,
				guideDisplayPath(consumed),
				parentInvocation,
			)
		}
		return nil, fmt.Errorf(
			"%w: unknown component %q under %q; try '%s'",
			errGuidePath,
			component,
			guideDisplayPath(parentPath),
			parentInvocation,
		)
	}
	return current, nil
}

func publicGuideChildren(command *cobra.Command) []*cobra.Command {
	children := make([]*cobra.Command, 0, len(command.Commands()))
	for _, child := range command.Commands() {
		if child.Hidden || child.Deprecated != "" {
			continue
		}
		if !child.Runnable() && !child.HasSubCommands() {
			continue
		}
		children = append(children, child)
	}
	sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
	return children
}

func aliasHasPrefix(command *cobra.Command, prefix string) bool {
	for _, alias := range command.Aliases {
		if strings.HasPrefix(alias, prefix) {
			return true
		}
	}
	return false
}

func canonicalGuideKey(root, command *cobra.Command) string {
	if command == root {
		return ""
	}
	var path []string
	for current := command; current != nil && current != root; current = current.Parent() {
		path = append(path, current.Name())
	}
	for left, right := 0, len(path)-1; left < right; left, right = left+1, right-1 {
		path[left], path[right] = path[right], path[left]
	}
	return strings.Join(path, " ")
}

func guideCommandPath(root, command *cobra.Command) string {
	key := canonicalGuideKey(root, command)
	if key == "" {
		return root.Name()
	}
	return root.Name() + " " + key
}

func guideDisplayPath(key string) string {
	if key == "" {
		return "swys"
	}
	return "swys " + key
}

func writeGuide(writer io.Writer, contents []byte) error {
	_, err := io.Copy(writer, bytes.NewReader(contents))
	if err != nil {
		return fmt.Errorf("copy rendered guide: %w", err)
	}
	return nil
}

// IsGuideCommand reports whether command is the curated guide command.
func IsGuideCommand(command *cobra.Command) bool {
	return command.Annotations[guideCommandShape] == commandShapeEnabled
}
