package cmd

import (
	"fmt"
	"testing"

	"github.com/spf13/cobra"
)

func TestCommandTreeConformsToNounVerbGrammar(t *testing.T) {
	for _, violation := range commandTreeViolations(rootCmd) {
		t.Error(violation)
	}
}

func TestCommandTreeRejectsUnclassifiedLeaf(t *testing.T) {
	root := &cobra.Command{Use: "root"}
	group := &cobra.Command{Use: "noun"}
	group.AddCommand(&cobra.Command{Use: "inspect", Run: func(*cobra.Command, []string) {}})
	root.AddCommand(group)

	violations := commandTreeViolations(root)
	if len(violations) != 1 || violations[0] != `leaf command "root noun inspect" has no output shape` {
		t.Fatalf("violations = %q, want missing output shape", violations)
	}
}

func commandTreeViolations(root *cobra.Command) []string {
	// Cobra's generated help/completion trees are outside npc's command grammar.
	verbs := map[string]bool{
		"connect":  true,
		"decrypt":  true,
		"encrypt":  true,
		"generate": true,
		"inspect":  true,
		// genkey is the documented one-release compatibility exception.
		"genkey": true,
	}

	var violations []string
	var walk func(*cobra.Command)
	walk = func(command *cobra.Command) {
		for _, child := range command.Commands() {
			if child.Name() == "completion" || child.Name() == "help" {
				continue
			}

			if child.HasSubCommands() {
				if (child.Run != nil || child.RunE != nil) && !commandHasShape(child, compatibilityShape) {
					violations = append(violations, fmt.Sprintf("group command %q must not be runnable", child.CommandPath()))
				}
			} else {
				if !verbs[child.Name()] {
					violations = append(violations, fmt.Sprintf("leaf command %q is not an allowed verb", child.CommandPath()))
				}
				binary := commandHasShape(child, binaryOutputShape)
				structured := commandHasShape(child, structuredOutputShape)
				switch {
				case !binary && !structured:
					violations = append(violations, fmt.Sprintf("leaf command %q has no output shape", child.CommandPath()))
				case binary && structured:
					violations = append(violations, fmt.Sprintf("leaf command %q has conflicting output shapes", child.CommandPath()))
				case binary && child.Flags().Lookup(encodingFlagName) == nil:
					violations = append(violations, fmt.Sprintf("binary command %q has no --encoding flag", child.CommandPath()))
				case structured && child.Flags().Lookup(formatFlagName) == nil:
					violations = append(violations, fmt.Sprintf("structured command %q has no --format flag", child.CommandPath()))
				}
			}

			if commandHasShape(child, networkShape) && child.Flags().Lookup("timeout") == nil {
				violations = append(violations, fmt.Sprintf("network command %q has no --timeout flag", child.CommandPath()))
			}
			if child.Flags().Lookup("output-format") != nil {
				violations = append(violations, fmt.Sprintf("command %q still exposes --output-format", child.CommandPath()))
			}
			walk(child)
		}
	}
	walk(root)
	return violations
}
