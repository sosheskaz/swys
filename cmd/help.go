package cmd

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	guideCommandShape = "guide"
	defaultGuideWidth = 80
)

var (
	errGuideOperationalFlag = errors.New("guide command does not accept operational I/O flags")
	errInvalidPager         = errors.New("invalid PAGER")
	errGuideNotFound        = errors.New("embedded guide not found")
	errGuidePath            = errors.New("invalid guide path")
	errEmbeddedGuide        = errors.New("invalid embedded guide")

	//go:embed guides
	embeddedGuideFiles embed.FS

	embeddedGuidesOnce sync.Once
	embeddedGuides     map[string][]byte
	errEmbeddedGuides  error
)

type guideDependencies struct {
	getenv   func(string) (string, bool)
	terminal func(io.Writer) (bool, int)
	command  func(context.Context, string, ...string) *exec.Cmd
}

func defaultGuideDependencies() guideDependencies {
	return guideDependencies{
		getenv:   os.LookupEnv,
		terminal: guideTerminal,
		command:  exec.CommandContext,
	}
}

func (dependencies guideDependencies) withDefaults() guideDependencies {
	defaults := defaultGuideDependencies()
	if dependencies.getenv == nil {
		dependencies.getenv = defaults.getenv
	}
	if dependencies.terminal == nil {
		dependencies.terminal = defaults.terminal
	}
	if dependencies.command == nil {
		dependencies.command = defaults.command
	}
	return dependencies
}

func configureGuideHelp(root *cobra.Command, dependencies guideDependencies) {
	dependencies = dependencies.withDefaults()
	referenceHelp := root.HelpFunc()
	root.SetHelpFunc(func(command *cobra.Command, args []string) {
		referenceHelp(command, args)
		key := canonicalGuideKey(root, command)
		if _, ok := guideSource(key); !ok {
			return
		}
		invocation := "npc help"
		if key != "" {
			invocation += " " + key
		}
		if _, err := fmt.Fprintf(command.OutOrStdout(), "\nFor a usage guide, run '%s'.\n", invocation); err != nil {
			command.PrintErrf("write usage-guide pointer: %v\n", err)
		}
	})

	root.SetHelpCommand(newGuideCommand(root, dependencies))
}

func newGuideCommand(root *cobra.Command, dependencies guideDependencies) *cobra.Command {
	var rich bool
	var plain bool
	var noPager bool

	command := &cobra.Command{
		Use:   "help [command path]",
		Short: "Read a curated guide for a command",
		Long: `Read a curated guide for an npc command.

Use a command's --help flag for its generated arguments and flags reference.`,
		Args: cobra.ArbitraryArgs,
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
			parent, err := resolveGuideTarget(root, args)
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
			return runGuide(command, root, dependencies, args, guideOptions{
				rich: rich, plain: plain, noPager: noPager,
			})
		},
	}
	command.Flags().BoolVar(&rich, "rich", false, "force rendered ANSI presentation")
	command.Flags().BoolVar(&plain, "plain", false, "force plain rendered text")
	command.Flags().BoolVar(&noPager, "no-pager", false, "write directly instead of using PAGER")
	command.MarkFlagsMutuallyExclusive("rich", "plain")
	addCommandShape(command, guideCommandShape)
	return command
}

type guideOptions struct {
	rich    bool
	plain   bool
	noPager bool
}

func runGuide(
	command *cobra.Command,
	root *cobra.Command,
	dependencies guideDependencies,
	path []string,
	options guideOptions,
) error {
	for _, flagName := range []string{"input", "output", "mode"} {
		flag := command.Flags().Lookup(flagName)
		if flag != nil && flag.Changed {
			return fmt.Errorf(
				"%w: --%s; use shell redirection to save a guide",
				errGuideOperationalFlag,
				flagName,
			)
		}
	}

	target, err := resolveGuideTarget(root, path)
	if err != nil {
		return err
	}
	key := canonicalGuideKey(root, target)
	guides, err := loadEmbeddedGuides()
	if err != nil {
		return fmt.Errorf("load embedded guides: %w", err)
	}
	source, ok := guides[key]
	if !ok {
		reference := "npc --help"
		if key != "" {
			reference = "npc " + key + " --help"
		}
		return fmt.Errorf(
			"%w for %q; run '%s' for reference help",
			errGuideNotFound,
			guideDisplayPath(key),
			reference,
		)
	}

	stdout := command.OutOrStdout()
	isTerminal, terminalWidth := dependencies.terminal(stdout)
	pager, pagerSet := dependencies.getenv("PAGER")
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
	dependencies guideDependencies,
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
	if value, ok := dependencies.getenv("NO_COLOR"); ok && value != "" {
		return false
	}
	if value, ok := dependencies.getenv("TERM"); ok && value == "dumb" {
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
	file, ok := writer.(interface{ Fd() uintptr })
	if !ok {
		return false, 0
	}
	fd := int(file.Fd())
	if !term.IsTerminal(fd) {
		return false, 0
	}
	width, _, err := term.GetSize(fd)
	if err != nil {
		return true, 0
	}
	return true, width
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
		parentInvocation := "npc help"
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
		return "npc"
	}
	return "npc " + key
}

func guideSource(key string) ([]byte, bool) {
	guides, err := loadEmbeddedGuides()
	if err != nil {
		return nil, false
	}
	source, ok := guides[key]
	return source, ok
}

func loadEmbeddedGuides() (map[string][]byte, error) {
	embeddedGuidesOnce.Do(func() {
		embeddedGuides = make(map[string][]byte)
		walkErr := fs.WalkDir(embeddedGuideFiles, "guides", func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return fmt.Errorf("walk embedded guide %q: %w", path, walkErr)
			}
			if entry.IsDir() || filepath.Ext(path) != ".md" {
				return nil
			}
			contents, err := embeddedGuideFiles.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read embedded guide %q: %w", path, err)
			}
			key := strings.TrimSuffix(strings.TrimPrefix(filepath.ToSlash(path), "guides/"), ".md")
			if key == "root" {
				key = ""
			} else {
				key = strings.ReplaceAll(key, "/", " ")
			}
			if len(bytes.TrimSpace(contents)) == 0 {
				return fmt.Errorf("%w: guide %q is empty", errEmbeddedGuide, path)
			}
			if _, exists := embeddedGuides[key]; exists {
				return fmt.Errorf("%w: duplicate mapping for %q", errEmbeddedGuide, key)
			}
			embeddedGuides[key] = contents
			return nil
		})
		if walkErr != nil {
			errEmbeddedGuides = fmt.Errorf("walk embedded guides: %w", walkErr)
			embeddedGuides = nil
		}
	})
	return embeddedGuides, errEmbeddedGuides
}

func writeGuide(writer io.Writer, contents []byte) error {
	_, err := io.Copy(writer, bytes.NewReader(contents))
	if err != nil {
		return fmt.Errorf("copy rendered guide: %w", err)
	}
	return nil
}
