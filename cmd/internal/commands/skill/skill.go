// Package skill prints the agent instructions bundled with the running binary.
package skill

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"strconv"
	"text/template"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/help"
	"github.com/sosheskaz/swys/internal/version"
)

//go:embed SKILL.md.tmpl
var instructions string

//go:embed guides/root.md
var guideFiles embed.FS

// NewCommand constructs the output-only skill command for one root lifecycle.
func NewCommand(lifecycle *commandio.Lifecycle) *cobra.Command {
	command := &cobra.Command{
		Use:   "skill",
		Short: "Print agent instructions for this SwYS build",
		Args:  cobra.NoArgs,
		RunE:  runSkill,
	}
	commandio.AddShape(command, "skill-document")
	lifecycle.Register(command, commandio.Behavior{
		SupportsOutput: true,
		Prepare: func(_ *cobra.Command, _ io.Reader) ([]byte, error) {
			return render(version.Get())
		},
	})
	if err := help.RegisterGuides(command, guideFiles); err != nil {
		panic(err)
	}
	return command
}

func render(info version.Info) ([]byte, error) {
	if info.Version == "" {
		info.Version = "unknown"
	}
	document, err := template.New("skill").Funcs(template.FuncMap{"quote": strconv.Quote}).Parse(instructions)
	if err != nil {
		return nil, fmt.Errorf("parse skill template: %w", err)
	}
	var output bytes.Buffer
	if err := document.Execute(&output, struct{ Version, Build string }{info.Version, info.String()}); err != nil {
		return nil, fmt.Errorf("render skill: %w", err)
	}
	return output.Bytes(), nil
}

func runSkill(command *cobra.Command, _ []string) error {
	document, output, err := commandio.TakePrepared(command)
	if err != nil {
		return fmt.Errorf("take prepared skill: %w", err)
	}
	n, err := output.Write(document)
	if err != nil {
		return fmt.Errorf("write skill: %w", err)
	}
	if n != len(document) {
		return fmt.Errorf("write skill: %w", io.ErrShortWrite)
	}
	return nil
}
