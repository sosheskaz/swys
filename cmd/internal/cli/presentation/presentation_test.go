package presentation_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/cli/presentation"
)

func TestPresentationPolicy(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, style, format, output, encoding, noColor, term string
		stdoutTerminal, stderrTerminal, wantOut, wantErr     bool
		width, wantWidth                                     int
	}{
		{name: "terminal", stdoutTerminal: true, stderrTerminal: true, wantOut: true, wantErr: true, width: 80, wantWidth: 80},
		{name: "redirect", stderrTerminal: true, wantErr: true, width: 80, wantWidth: 100},
		{name: "file", output: "report.txt", stdoutTerminal: true, stderrTerminal: true, wantErr: true, width: 80, wantWidth: 100},
		{name: "encoding", encoding: "base64", stdoutTerminal: true, stderrTerminal: true, wantErr: true, width: 80, wantWidth: 100},
		{name: "no-color", noColor: "1", stdoutTerminal: true, stderrTerminal: true, width: 80, wantWidth: 80},
		{name: "dumb", term: "dumb", stdoutTerminal: true, stderrTerminal: true, width: 80, wantWidth: 80},
		{name: "forced-rich", style: "rich", noColor: "1", term: "dumb", wantOut: true, wantErr: true, width: 80, wantWidth: 100},
		{name: "forced-rich-file", style: "rich", output: "report.txt", stdoutTerminal: true, wantOut: true, wantErr: true, width: 40, wantWidth: 100},
		{name: "plain-style", style: "plain", stdoutTerminal: true, stderrTerminal: true, width: 80, wantWidth: 80},
		{name: "plain-format-wins", format: "plain", style: "rich", stdoutTerminal: true, stderrTerminal: true, width: 80, wantWidth: 80},
		{name: "wide", stdoutTerminal: true, wantOut: true, width: 120, wantWidth: 120},
		{name: "unknown-width", stdoutTerminal: true, wantOut: true, wantWidth: 100},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := &cobra.Command{Use: "test"}
			presentation.AddFlags(root)
			for flag, value := range map[string]string{"format": test.format, "output": test.output, "encoding": test.encoding} {
				if flag == "encoding" && value == "" {
					value = "raw"
				}
				root.Flags().String(flag, value, "test flag")
			}
			if test.style != "" {
				require.NoError(t, root.PersistentFlags().Set("style", test.style))
			}
			var stdout, stderr bytes.Buffer
			root.SetOut(&stdout)
			root.SetErr(&stderr)
			original := presentation.WithDependencies(t.Context(), presentation.Dependencies{
				Terminal: func(writer io.Writer) (bool, int) {
					if writer == &stdout {
						return test.stdoutTerminal, test.width
					}
					return test.stderrTerminal, test.width
				},
				Getenv: func(name string) (string, bool) {
					value := map[string]string{"NO_COLOR": test.noColor, "TERM": test.term}[name]
					return value, value != ""
				},
			})
			root.SetContext(original)
			restore, err := presentation.Resolve(root)
			require.NoError(t, err)
			assert.Equal(t, test.wantOut, presentation.Output(root).Rich)
			assert.Equal(t, test.wantErr, presentation.Diagnostics(root).Rich)
			assert.Equal(t, test.wantWidth, presentation.Output(root).Width)
			restore()
			assert.Equal(t, original, root.Context())
		})
	}
}

var errOperation = errors.New("operation failed")

func TestFinalErrorOnlyStylesPrefix(t *testing.T) {
	t.Parallel()
	failure := errOperation
	for _, style := range []string{"rich", "plain", "invalid"} {
		root := &cobra.Command{Use: "swys"}
		presentation.AddFlags(root)
		require.NoError(t, root.PersistentFlags().Set("style", style))
		root.SetContext(presentation.WithDependencies(t.Context(), presentation.Dependencies{
			Terminal: func(io.Writer) (bool, int) { return false, 0 },
		}))
		var output bytes.Buffer
		root.SetErr(&output)
		require.NoError(t, presentation.WriteError(root, failure))
		want := "swys: operation failed\n"
		if style == "rich" {
			want = "\x1b[31mswys:\x1b[0m operation failed\n"
		}
		assert.Equal(t, want, output.String())
	}
}
