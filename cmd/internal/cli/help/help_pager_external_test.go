package help_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/cli/help"
)

func TestGuideRenderingAndPagerSelectionMatrix(t *testing.T) {
	t.Parallel()

	pager := guidePagerHelperCommand("copy")
	tests := []struct {
		name       string
		env        map[string]string
		args       []string
		terminal   bool
		wantRich   bool
		wantOutput bool
	}{
		{name: "direct-terminal", terminal: true, wantRich: true, wantOutput: true},
		{name: "terminal-pager", terminal: true, env: map[string]string{"PAGER": pager}, wantOutput: true},
		{name: "forced-rich-pager", terminal: true, env: map[string]string{"PAGER": pager}, args: []string{"--rich"}, wantRich: true, wantOutput: true},
		{name: "forced-rich-pipe", args: []string{"--rich"}, wantRich: true, wantOutput: true},
		{name: "forced-plain-terminal", terminal: true, args: []string{"--plain"}, wantOutput: true},
		{name: "no-pager", terminal: true, env: map[string]string{"PAGER": pager}, args: []string{"--no-pager"}, wantRich: true, wantOutput: true},
		{name: "redirected-with-pager", env: map[string]string{"PAGER": pager}, wantOutput: true},
		{name: "no-color", terminal: true, env: map[string]string{"NO_COLOR": "1"}, wantOutput: true},
		{name: "dumb-terminal", terminal: true, env: map[string]string{"TERM": "dumb"}, wantOutput: true},
		{name: "empty-pager", terminal: true, env: map[string]string{"PAGER": ""}, wantRich: true, wantOutput: true},
		{
			name: "rich-overrides-environment", terminal: true,
			env: map[string]string{"NO_COLOR": "1", "TERM": "dumb"}, args: []string{"--rich"},
			wantRich: true, wantOutput: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := []string{"help", "net"}
			args = append(args, test.args...)
			stdout, stderr, err := executeRootCommandStreams(t, newGuideTestRoot(test.terminal, 61, test.env), args...)
			require.NoError(t, err)
			if test.wantOutput {
				require.Contains(t, stripGuideANSI(stdout), "Exchange raw bytes")
			}
			require.Equal(t, test.wantRich, strings.Contains(stdout, "\x1b["), "rich output: %q", stdout)
			require.Empty(t, stderr)
		})
	}
}

func TestGuideRenderingFlagsAreMutuallyExclusive(t *testing.T) {
	t.Parallel()

	stdout, _, err := executeRootCommandStreams(t, newGuideTestRoot(false, 0, nil), "help", "--rich", "--plain")
	require.ErrorContains(t, err, "if any flags in the group")
	require.Empty(t, stdout)
}

func TestGuideLayoutUsesOriginalTerminalWidth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		env      map[string]string
		name     string
		terminal bool
		width    int
		wantMax  int
		wantOver int
	}{
		{name: "direct-terminal", terminal: true, width: 34, wantMax: 34},
		{name: "pager-terminal", terminal: true, width: 31, env: map[string]string{"PAGER": guidePagerHelperCommand("copy")}, wantMax: 31},
		{name: "redirect-uses-eighty", width: 20, wantMax: 80, wantOver: 34},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			stdout, _, err := executeRootCommandStreams(
				t,
				newGuideTestRoot(test.terminal, test.width, test.env),
				"help", "--plain",
			)
			require.NoError(t, err)
			paragraph := firstGuideParagraphLines(stdout)
			require.NotEmpty(t, paragraph, "first paragraph in %q", stdout)
			longest := 0
			for _, line := range paragraph {
				if width := len([]rune(line)); width > longest {
					longest = width
				}
			}
			assert.LessOrEqual(t, longest, test.wantMax, "paragraph lines %q", paragraph)
			assert.Greater(t, longest, test.wantOver, "paragraph lines %q", paragraph)
		})
	}
}

func TestGuidePagerReceivesQuotedArgumentsAndInheritedEnvironment(t *testing.T) {
	const environmentName = "SWYS_HELP_PAGER_INHERITED_TEST"
	t.Setenv(environmentName, "visible")
	marker := filepath.Join(t.TempDir(), "pager-record")
	pager := guidePagerHelperCommand("record", marker, "two words", environmentName)
	root := newGuideTestRoot(true, 80, map[string]string{"PAGER": pager})
	stdout, stderr, err := executeRootCommandStreams(t, root, "help", "cert", "--plain")
	require.NoError(t, err)
	require.Contains(t, stdout, "Work with X.509 certificates")
	require.Empty(t, stderr)
	record, err := os.ReadFile(marker)
	require.NoError(t, err, "pager reaped after recording input")
	for _, want := range []string{"argument=two words\n", "environment=visible\n", "Work with X.509 certificates"} {
		assert.Contains(t, string(record), want, "pager record")
	}
}

func TestGuidePagerStartupFailureWarnsAndFallsBack(t *testing.T) {
	t.Parallel()

	root := newGuideTestRoot(true, 80, map[string]string{"PAGER": filepath.Join(t.TempDir(), "missing-pager")})
	stdout, stderr, err := executeRootCommandStreams(t, root, "help", "dns")
	require.NoError(t, err)
	require.Contains(t, stdout, "Resolve DNS names and records")
	require.NotContains(t, stdout, "\x1b[", "plain fallback output")
	assert.Contains(t, stderr, "warning: could not start pager")
	assert.Contains(t, stderr, "writing guide directly")
}

func TestGuidePagerPipeSetupFailureWarnsAndFallsBack(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	dependencies := defaultGuideDependencies()
	dependencies.Command = pagerCommandWithOccupiedStdin
	require.NoError(t, presentGuideThroughPager(command, dependencies, "unused", []byte("rendered guide\n")))
	assert.Equal(t, "rendered guide\n", stdout.String())
	assert.Contains(t, stderr.String(), "could not start pager")
}

func TestGuidePagerFallbackPropagatesOutputFailure(t *testing.T) {
	t.Parallel()

	command := &cobra.Command{}
	command.SetOut(guideFailingWriter{err: errGuideWriter})
	command.SetErr(io.Discard)
	dependencies := defaultGuideDependencies()
	dependencies.Command = pagerCommandWithOccupiedStdin
	err := presentGuideThroughPager(command, dependencies, "unused", []byte("rendered guide\n"))
	require.ErrorIs(t, err, errGuideWriter)
}

func TestGuideMalformedPagerConfigurationIsAnError(t *testing.T) {
	t.Parallel()

	root := newGuideTestRoot(true, 80, map[string]string{"PAGER": "'unterminated"})
	stdout, stderr, err := executeRootCommandStreams(t, root, "help", "dns")
	require.ErrorIs(t, err, errInvalidPager)
	assert.Empty(t, stdout)
	assert.Empty(t, stderr)
}

func TestGuideRedirectAndNoPagerNeverStartConfiguredPager(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		args     []string
		terminal bool
	}{
		{name: "redirect", args: []string{"--rich"}},
		{name: "no-pager", terminal: true, args: []string{"--no-pager"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			marker := filepath.Join(t.TempDir(), "unexpected-pager")
			pager := guidePagerHelperCommand("record", marker, "unused", "PATH")
			args := []string{"help", "net"}
			args = append(args, test.args...)
			_, _, err := executeRootCommandStreams(t, newGuideTestRoot(test.terminal, 80, map[string]string{"PAGER": pager}), args...)
			require.NoError(t, err)
			if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("configured pager started unexpectedly: %v", statErr)
			}
		})
	}
}

func TestGuidePagerSuccessfulEarlyExitSuppressesBrokenPipe(t *testing.T) {
	t.Parallel()

	command := &cobra.Command{}
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	dependencies := defaultGuideDependencies()
	rendered := bytes.Repeat([]byte("a long rendered guide line\n"), 128*1024)
	assert.NoError(t, presentGuideThroughPager(command, dependencies, guidePagerHelperCommand("early-exit"), rendered), "successful early pager exit")
}

func TestGuidePagerReportsNonzeroExit(t *testing.T) {
	t.Parallel()

	command := &cobra.Command{}
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	err := presentGuideThroughPager(command, defaultGuideDependencies(), guidePagerHelperCommand("fail"), []byte("guide\n"))
	require.ErrorContains(t, err, "pager")
	require.ErrorContains(t, err, "exit status")
}

func TestGuidePagerHelperProcess(t *testing.T) { //nolint:paralleltest // subprocess branch exits the test process
	markerIndex := slices.Index(os.Args, "swys-help-pager")
	if markerIndex < 0 {
		t.Parallel()

		return
	}
	arguments := os.Args[markerIndex+1:]
	if len(arguments) == 0 {
		os.Exit(91)
	}
	switch arguments[0] {
	case "copy":
		_, err := io.Copy(os.Stdout, os.Stdin)
		if err != nil {
			os.Exit(92)
		}
		os.Exit(0)
	case "record":
		if len(arguments) != 4 {
			os.Exit(93)
		}
		contents, err := io.ReadAll(os.Stdin)
		if err != nil {
			os.Exit(94)
		}
		record := []byte("argument=" + arguments[2] + "\nenvironment=" + os.Getenv(arguments[3]) + "\n")
		record = append(record, contents...)
		if err := os.WriteFile(arguments[1], record, 0o600); err != nil {
			os.Exit(95)
		}
		if _, err := os.Stdout.Write(contents); err != nil {
			os.Exit(96)
		}
		os.Exit(0)
	case "early-exit":
		os.Exit(0)
	case "hold":
		if len(arguments) != 3 {
			os.Exit(99)
		}
		if err := os.WriteFile(arguments[1], []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			os.Exit(94)
		}
		for {
			if _, err := os.Stat(arguments[2]); err == nil {
				os.Exit(0)
			}
			time.Sleep(10 * time.Millisecond)
		}
	case "fail":
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			os.Exit(98)
		}
		os.Exit(7)
	default:
		os.Exit(97)
	}
}

func guidePagerHelperCommand(action string, arguments ...string) string {
	parts := []string{
		quotePagerTestArgument(os.Args[0]),
		"-test.run=^TestGuidePagerHelperProcess$",
		"--",
		"swys-help-pager",
		action,
	}
	for _, argument := range arguments {
		parts = append(parts, quotePagerTestArgument(argument))
	}
	return strings.Join(parts, " ")
}

func pagerCommandWithOccupiedStdin(ctx context.Context, _ string, _ ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, "unused")
	command.Stdin = strings.NewReader("occupied")
	return command
}

var (
	errInvalidPager = help.ErrInvalidPager
	errGuideWriter  = errors.New("guide writer failed")
)

type guideFailingWriter struct{ err error }

func (writer guideFailingWriter) Write([]byte) (int, error) { return 0, writer.err }

func defaultGuideDependencies() help.Dependencies { return help.DefaultDependencies() }

func presentGuideThroughPager(command *cobra.Command, dependencies help.Dependencies, configuration string, rendered []byte) error {
	return help.PresentGuideThroughPagerForTest(command, dependencies, configuration, rendered)
}

func quotePagerTestArgument(argument string) string {
	return "'" + strings.ReplaceAll(argument, "'", "'\\''") + "'"
}

func firstGuideParagraphLines(output string) []string {
	parts := strings.Split(output, "\n\n")
	if len(parts) < 2 {
		return nil
	}
	return strings.Split(parts[1], "\n")
}
