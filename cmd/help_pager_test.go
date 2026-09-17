package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestParsePagerQuotedArguments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		configuration string
		want          []string
	}{
		{name: "arguments", configuration: "less -R", want: []string{"less", "-R"}},
		{
			name:          "quoted-and-escaped",
			configuration: `'/path with spaces/pager' "two words" plain\ value ''`,
			want:          []string{"/path with spaces/pager", "two words", "plain value", ""},
		},
		{
			name:          "windows-paths",
			configuration: `"C:\Program Files\pager.exe" "--theme=C:\Themes\dark"`,
			want:          []string{`C:\Program Files\pager.exe`, `--theme=C:\Themes\dark`},
		},
		{
			name:          "escaped-quote-in-double-quotes",
			configuration: `pager "say \"hello\""`,
			want:          []string{"pager", `say "hello"`},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := parsePager(test.configuration)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, test.want) {
				t.Fatalf("parsePager(%q) = %q, want %q", test.configuration, got, test.want)
			}
		})
	}
}

func TestParsePagerRejectsMalformedConfiguration(t *testing.T) {
	t.Parallel()

	for _, configuration := range []string{"", "   ", "'unterminated", `"unterminated`, "pager\\"} {
		t.Run(fmt.Sprintf("%q", configuration), func(t *testing.T) {
			t.Parallel()
			if _, err := parsePager(configuration); !errors.Is(err, errInvalidPager) {
				t.Fatalf("error = %v, want errInvalidPager", err)
			}
		})
	}
}

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
			if err != nil {
				t.Fatal(err)
			}
			if test.wantOutput && !strings.Contains(stripGuideANSI(stdout), "Exchange raw bytes") {
				t.Fatalf("stdout does not contain guide: %q", stdout)
			}
			if gotRich := strings.Contains(stdout, "\x1b["); gotRich != test.wantRich {
				t.Fatalf("rich output = %t, want %t: %q", gotRich, test.wantRich, stdout)
			}
			if stderr != "" {
				t.Fatalf("stderr = %q, want no diagnostics", stderr)
			}
		})
	}
}

func TestGuideRenderingFlagsAreMutuallyExclusive(t *testing.T) {
	t.Parallel()

	stdout, _, err := executeRootCommandStreams(t, newGuideTestRoot(false, 0, nil), "help", "--rich", "--plain")
	if err == nil || !strings.Contains(err.Error(), "if any flags in the group") {
		t.Fatalf("error = %v, want mutual-exclusion diagnostic", err)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no rendered guide", stdout)
	}
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
			if err != nil {
				t.Fatal(err)
			}
			paragraph := firstGuideParagraphLines(stdout)
			if len(paragraph) == 0 {
				t.Fatalf("could not locate first paragraph in %q", stdout)
			}
			longest := 0
			for _, line := range paragraph {
				if width := len([]rune(line)); width > longest {
					longest = width
				}
			}
			if longest > test.wantMax || longest <= test.wantOver {
				t.Fatalf("first paragraph longest line = %d, want (%d, %d] lines %q", longest, test.wantOver, test.wantMax, paragraph)
			}
		})
	}
}

func TestGuidePagerReceivesQuotedArgumentsAndInheritedEnvironment(t *testing.T) {
	const environmentName = "NPC_HELP_PAGER_INHERITED_TEST"
	t.Setenv(environmentName, "visible")
	marker := filepath.Join(t.TempDir(), "pager-record")
	pager := guidePagerHelperCommand("record", marker, "two words", environmentName)
	root := newGuideTestRoot(true, 80, map[string]string{"PAGER": pager})
	stdout, stderr, err := executeRootCommandStreams(t, root, "help", "cert", "--plain")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Work with X.509 certificates") || stderr != "" {
		t.Fatalf("stdout = %q, stderr = %q", stdout, stderr)
	}
	record, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("pager was not reaped after recording input: %v", err)
	}
	for _, want := range []string{"argument=two words\n", "environment=visible\n", "Work with X.509 certificates"} {
		if !bytes.Contains(record, []byte(want)) {
			t.Errorf("pager record does not contain %q:\n%s", want, record)
		}
	}
}

func TestGuidePagerStartupFailureWarnsAndFallsBack(t *testing.T) {
	t.Parallel()

	root := newGuideTestRoot(true, 80, map[string]string{"PAGER": filepath.Join(t.TempDir(), "missing-pager")})
	stdout, stderr, err := executeRootCommandStreams(t, root, "help", "dns")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Resolve DNS names and records") || strings.Contains(stdout, "\x1b[") {
		t.Fatalf("fallback stdout = %q, want plain rendered guide", stdout)
	}
	if !strings.Contains(stderr, "warning: could not start pager") || !strings.Contains(stderr, "writing guide directly") {
		t.Fatalf("stderr = %q, want concise fallback warning", stderr)
	}
}

func TestGuidePagerPipeSetupFailureWarnsAndFallsBack(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	dependencies := defaultGuideDependencies()
	dependencies.command = pagerCommandWithOccupiedStdin
	if err := presentGuideThroughPager(command, dependencies, "unused", []byte("rendered guide\n")); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "rendered guide\n" || !strings.Contains(stderr.String(), "could not start pager") {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestGuidePagerFallbackPropagatesOutputFailure(t *testing.T) {
	t.Parallel()

	command := &cobra.Command{}
	command.SetOut(guideFailingWriter{err: errGuideWriter})
	command.SetErr(io.Discard)
	dependencies := defaultGuideDependencies()
	dependencies.command = pagerCommandWithOccupiedStdin
	err := presentGuideThroughPager(command, dependencies, "unused", []byte("rendered guide\n"))
	if !errors.Is(err, errGuideWriter) {
		t.Fatalf("fallback error = %v, want guide writer failure", err)
	}
}

func TestGuideMalformedPagerConfigurationIsAnError(t *testing.T) {
	t.Parallel()

	root := newGuideTestRoot(true, 80, map[string]string{"PAGER": "'unterminated"})
	stdout, stderr, err := executeRootCommandStreams(t, root, "help", "dns")
	if !errors.Is(err, errInvalidPager) {
		t.Fatalf("error = %v, want errInvalidPager", err)
	}
	if stdout != "" || stderr != "" {
		t.Fatalf("stdout = %q, stderr = %q, want no partial output", stdout, stderr)
	}
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
			if err != nil {
				t.Fatal(err)
			}
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
	if err := presentGuideThroughPager(command, dependencies, guidePagerHelperCommand("early-exit"), rendered); err != nil {
		t.Fatalf("successful early pager exit: %v", err)
	}
}

func TestGuidePagerReportsNonzeroExit(t *testing.T) {
	t.Parallel()

	command := &cobra.Command{}
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	err := presentGuideThroughPager(command, defaultGuideDependencies(), guidePagerHelperCommand("fail"), []byte("guide\n"))
	if err == nil || !strings.Contains(err.Error(), "pager") || !strings.Contains(err.Error(), "exit status") {
		t.Fatalf("error = %v, want nonzero pager exit", err)
	}
}

func TestGuidePagerHelperProcess(t *testing.T) { //nolint:paralleltest // subprocess branch exits the test process
	markerIndex := slices.Index(os.Args, "npc-help-pager")
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
		"npc-help-pager",
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
