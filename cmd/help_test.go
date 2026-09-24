package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

var (
	errGuideTargetPreRun = errors.New("target pre-run executed")
	errGuideTargetRun    = errors.New("target handler executed")
	errGuideWriter       = errors.New("guide writer failed")
)

func TestEmbeddedGuidesCoverEveryPublicCommand(t *testing.T) {
	t.Parallel()

	root := initializedGuideRoot()
	guides, err := loadEmbeddedGuides()
	if err != nil {
		t.Fatal(err)
	}
	want := publicGuidePaths(root)
	got := make([]string, 0, len(guides))
	for path := range guides {
		got = append(got, path)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("embedded guide paths = %q, want public command paths %q", got, want)
	}

	for _, path := range want {
		command, err := resolveGuideTarget(root, strings.Fields(path))
		if err != nil {
			t.Fatalf("resolve canonical guide %q: %v", path, err)
		}
		source := guides[path]
		blocks, err := parseGuide(source)
		if err != nil {
			t.Fatalf("parse guide %q: %v", guideDisplayPath(path), err)
		}
		if command == root || len(publicGuideChildren(command)) > 0 {
			if !guideHasBlock(blocks, guideListBlock) {
				t.Errorf("root or branch guide %q has no chooser list", guideDisplayPath(path))
			}
		} else if !guideHasBlock(blocks, guideCodeBlock) {
			t.Errorf("leaf guide %q has no executable example", guideDisplayPath(path))
		}

		reference := "npc --help"
		if path != "" {
			reference = "npc " + path + " --help"
		}
		if !sourceHasCommand(source, reference) {
			t.Errorf("guide %q does not contain reference invocation %q", guideDisplayPath(path), reference)
		}
	}
}

func TestGuideNavigationReferencesResolveThroughCommandTree(t *testing.T) {
	t.Parallel()

	root := initializedGuideRoot()
	guides, err := loadEmbeddedGuides()
	if err != nil {
		t.Fatal(err)
	}
	navigation := regexp.MustCompile(`(?m)^npc help(?: ([^\r\n]+))?$`)
	for path, source := range guides {
		for _, match := range navigation.FindAllSubmatch(source, -1) {
			fields := strings.Fields(string(match[1]))
			if slices.ContainsFunc(fields, func(field string) bool { return strings.HasPrefix(field, "-") }) {
				continue
			}
			if _, err := resolveGuideTarget(root, fields); err != nil {
				t.Errorf("guide %q has unresolved navigation %q: %v", guideDisplayPath(path), match[0], err)
			}
		}
	}
}

func TestEveryEmbeddedGuideRendersPlainAndRich(t *testing.T) {
	t.Parallel()

	guides, err := loadEmbeddedGuides()
	if err != nil {
		t.Fatal(err)
	}
	for path, source := range guides {
		t.Run(strings.ReplaceAll(guideDisplayPath(path), " ", "_"), func(t *testing.T) {
			t.Parallel()
			plain, err := renderGuide(source, guideRenderOptions{width: 47})
			if err != nil {
				t.Fatal(err)
			}
			rich, err := renderGuide(source, guideRenderOptions{width: 47, rich: true})
			if err != nil {
				t.Fatal(err)
			}
			if len(plain) == 0 || bytes.Contains(plain, []byte("\x1b[")) || bytes.Contains(plain, []byte("```")) {
				t.Fatalf("plain guide contains raw presentation syntax: %q", plain)
			}
			if !bytes.Contains(rich, []byte("\x1b[")) {
				t.Fatalf("rich guide contains no styling: %q", rich)
			}
			plainLabels := regexp.MustCompile(`\s+\(https?://[^)]+\)`).ReplaceAllString(string(plain), "")
			if stripped := stripGuideANSI(string(rich)); strings.Join(strings.Fields(stripped), " ") != strings.Join(strings.Fields(plainLabels), " ") {
				t.Fatalf("rich and plain content differ\nrich: %q\nplain: %q", stripped, plain)
			}
		})
	}
}

func TestEveryCommandAliasCombinationResolvesCanonicalGuide(t *testing.T) {
	t.Parallel()

	root := initializedGuideRoot()
	var visit func(*cobra.Command, [][]string)
	visit = func(parent *cobra.Command, parentPaths [][]string) {
		for _, child := range publicGuideChildren(parent) {
			names := append([]string{child.Name()}, child.Aliases...)
			var childPaths [][]string
			for _, parentPath := range parentPaths {
				for _, name := range names {
					path := append(append([]string{}, parentPath...), name)
					resolved, err := resolveGuideTarget(root, path)
					if err != nil {
						t.Errorf("resolve alias path %q: %v", path, err)
						continue
					}
					if got, want := canonicalGuideKey(root, resolved), canonicalGuideKey(root, child); got != want {
						t.Errorf("alias path %q resolved to %q, want %q", path, got, want)
					}
					childPaths = append(childPaths, path)
				}
			}
			visit(child, childPaths)
		}
	}
	visit(root, [][]string{{}})
}

func TestHelpAliasesSelectCanonicalGuides(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		wantHeading string
		args        []string
	}{
		{name: "certificate-family", args: []string{"x509", "connect"}, wantHeading: "Inspect a TLS server's certificates"},
		{name: "certificate-leaf", args: []string{"certificate", "conn"}, wantHeading: "Inspect a TLS server's certificates"},
		{name: "punctuated-certificate", args: []string{"x.509", "c"}, wantHeading: "Inspect a TLS server's certificates"},
		{name: "network-family", args: []string{"nc", "connect"}, wantHeading: "Connect to a network endpoint"},
		{name: "network-long-alias", args: []string{"netcat", "listen"}, wantHeading: "Listen for one network exchange"},
		{name: "key-family-and-leaf", args: []string{"k", "gen"}, wantHeading: "Generate a cryptographic key"},
		{name: "key-leaf", args: []string{"key", "p"}, wantHeading: "Derive or canonicalize a public key"},
		{name: "aes-encrypt", args: []string{"aes", "enc"}, wantHeading: "Encrypt a message with AES"},
		{name: "aes-decrypt", args: []string{"aes", "d"}, wantHeading: "Decrypt an AES message"},
		{name: "dns", args: []string{"dig"}, wantHeading: "Resolve DNS names and records"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := append([]string{"help"}, test.args...)
			args = append(args, "--plain", "--no-pager")
			stdout, stderr, err := executeRootCommandStreams(t, newGuideTestRoot(false, 0, nil), args...)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(stdout, test.wantHeading+"\n") {
				t.Fatalf("stdout = %q, want heading %q", stdout, test.wantHeading)
			}
			if stderr != "" {
				t.Fatalf("stderr = %q, want no diagnostics", stderr)
			}
		})
	}
}

func TestHelpRejectsUnknownAndSurplusPathComponents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		wantErr string
		args    []string
	}{
		{name: "unknown-root", args: []string{"help", "missing"}, wantErr: "try 'npc help'"},
		{name: "unknown-child", args: []string{"help", "cert", "missing"}, wantErr: "try 'npc help cert'"},
		{name: "surplus-after-leaf", args: []string{"help", "cert", "connect", "extra"}, wantErr: "try 'npc help cert connect'"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			stdout, _, err := executeRootCommandStreams(t, newGuideTestRoot(false, 0, nil), test.args...)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want diagnostic containing %q", err, test.wantErr)
			}
			if stdout != "" {
				t.Fatalf("stdout = %q, want no fallback guide", stdout)
			}
		})
	}
}

func TestHelpRejectsOperationalIOFlagsWithoutSideEffects(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	for _, flag := range []string{"input", "output", "mode"} {
		t.Run(flag, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(directory, flag)
			value := path
			if flag == "mode" {
				value = "0600"
			}
			root := newGuideTestRoot(false, 0, nil)
			root.SetIn(guidePanicReader{})
			_, _, err := executeRootCommandStreams(t, root, "help", "cert", "connect", "--"+flag, value)
			if !errors.Is(err, errGuideOperationalFlag) {
				t.Fatalf("error = %v, want errGuideOperationalFlag", err)
			}
			if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("operational flag touched %q: %v", path, statErr)
			}
		})
	}
}

func TestHelpDoesNotRunTargetHooksOrHandlers(t *testing.T) {
	t.Parallel()

	root := newGuideTestRoot(false, 0, nil)
	target, err := resolveGuideTarget(root, []string{"cert", "connect"})
	if err != nil {
		t.Fatal(err)
	}
	preRunCalled := false
	runCalled := false
	target.PreRunE = func(*cobra.Command, []string) error {
		preRunCalled = true
		return errGuideTargetPreRun
	}
	target.RunE = func(*cobra.Command, []string) error {
		runCalled = true
		return errGuideTargetRun
	}
	root.SetIn(guidePanicReader{})
	stdout, stderr, err := executeRootCommandStreams(t, root, "help", "x509", "connect", "--plain")
	if err != nil {
		t.Fatal(err)
	}
	if preRunCalled || runCalled {
		t.Fatalf("target lifecycle ran: pre-run=%t handler=%t", preRunCalled, runCalled)
	}
	if stdout == "" || stderr != "" {
		t.Fatalf("stdout length = %d, stderr = %q", len(stdout), stderr)
	}
}

func TestReferenceHelpAndBareBranchesKeepTheirBehavior(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want string
		args []string
	}{
		{name: "bare-root", want: "Usage:\n  npc [command]"},
		{name: "bare-branch", args: []string{"net"}, want: "Usage:\n  npc net [command]"},
		{name: "bare-hash", args: []string{"hash"}, want: "Usage:\n  npc hash [flags]"},
		{name: "reference", args: []string{"net", "connect", "--tls", "--help"}, want: "Usage:\n  npc net connect host:port [flags]"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			stdout, stderr, err := executeRootStreams(t, test.args...)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(stdout, test.want) || !strings.Contains(stdout, "For a usage guide, run '") {
				t.Fatalf("stdout does not preserve reference output and guide pointer:\n%s", stdout)
			}
			if stderr != "" {
				t.Fatalf("stderr = %q", stderr)
			}
		})
	}

	stdout, _, err := executeRootCommandStreams(t, newGuideTestRoot(false, 0, nil), "net", "connect", "--tls")
	if err == nil || !strings.Contains(err.Error(), "accepts 1 arg(s), received 0") {
		t.Fatalf("missing operational argument error = %v", err)
	}
	if strings.Contains(stdout, "Exchange bytes over verified TLS") {
		t.Fatalf("runnable leaf unexpectedly fell back to guide: %q", stdout)
	}
}

func TestReferenceGuidePointerUsesStdoutWithDefaultStreams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		wantPointer string
		args        []string
	}{
		{name: "bare-root", wantPointer: "For a usage guide, run 'npc help'."},
		{name: "bare-branch", wantPointer: "For a usage guide, run 'npc help net'.", args: []string{"net"}},
		{
			name: "leaf-reference", wantPointer: "For a usage guide, run 'npc help cert connect'.",
			args: []string{"cert", "connect", "--help"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			arguments := []string{"-test.run=^TestGuideDefaultStreamsHelperProcess$", "--", "npc-help-default-streams"}
			arguments = append(arguments, test.args...)
			process := exec.CommandContext(t.Context(), os.Args[0], arguments...)
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			process.Stdout = &stdout
			process.Stderr = &stderr
			if err := process.Run(); err != nil {
				t.Fatalf("default-stream helper: %v; stderr: %s", err, stderr.String())
			}
			if !strings.Contains(stdout.String(), test.wantPointer) {
				t.Fatalf("stdout lacks guide pointer %q:\n%s", test.wantPointer, stdout.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want successful reference output only on stdout", stderr.String())
			}
		})
	}
}

func TestGuideDefaultStreamsHelperProcess(t *testing.T) { //nolint:paralleltest // subprocess branch exits the test process
	markerIndex := slices.Index(os.Args, "npc-help-default-streams")
	if markerIndex < 0 {
		t.Parallel()

		return
	}
	root := newRootCmd()
	root.SetArgs(os.Args[markerIndex+1:])
	if err := root.Execute(); err != nil {
		os.Exit(98)
	}
	os.Exit(0)
}

func TestEveryPublicCommandReferenceHelpPointsToItsGuide(t *testing.T) {
	t.Parallel()

	for _, path := range publicGuidePaths(initializedGuideRoot()) {
		t.Run(strings.ReplaceAll(guideDisplayPath(path), " ", "_"), func(t *testing.T) {
			t.Parallel()

			args := strings.Fields(path)
			args = append(args, "--help")
			stdout, stderr, err := executeRootStreams(t, args...)
			if err != nil {
				t.Fatal(err)
			}
			invocation := "npc help"
			if path != "" {
				invocation += " " + path
			}
			if !strings.Contains(stdout, "For a usage guide, run '"+invocation+"'.") {
				t.Fatalf("reference help lacks guide pointer %q:\n%s", invocation, stdout)
			}
			if stderr != "" {
				t.Fatalf("stderr = %q", stderr)
			}
		})
	}
}

func TestHelpCompletesCanonicalCommandPaths(t *testing.T) {
	t.Parallel()

	root := initializedGuideRoot()
	help, err := resolveGuideTarget(root, []string{"help"})
	if err != nil {
		t.Fatal(err)
	}
	completions, directive := help.ValidArgsFunction(help, []string{"x509"}, "c")
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("directive = %v, want no file completion", directive)
	}
	hasConnect := slices.ContainsFunc(completions, func(completion cobra.Completion) bool {
		return strings.HasPrefix(completion, "connect")
	})
	if !hasConnect {
		t.Fatalf("completions = %q, want canonical connect path", completions)
	}
	completions, _ = help.ValidArgsFunction(help, nil, "x")
	hasCert := slices.ContainsFunc(completions, func(completion cobra.Completion) bool {
		return strings.HasPrefix(completion, "cert")
	})
	if !hasCert {
		t.Fatalf("alias completions = %q, want canonical cert path", completions)
	}
}

func TestGuideDependenciesDefaultAndDetectNonterminalWriters(t *testing.T) {
	t.Parallel()

	dependencies := (guideDependencies{}).withDefaults()
	if dependencies.getenv == nil || dependencies.terminal == nil || dependencies.command == nil {
		t.Fatal("default guide dependencies are incomplete")
	}
	if terminal, width := dependencies.terminal(&bytes.Buffer{}); terminal || width != 0 {
		t.Fatalf("buffer terminal result = (%t, %d), want (false, 0)", terminal, width)
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := errors.Join(reader.Close(), writer.Close()); err != nil {
			t.Errorf("close terminal test pipe: %v", err)
		}
	})
	if terminal, width := dependencies.terminal(writer); terminal || width != 0 {
		t.Fatalf("pipe terminal result = (%t, %d), want (false, 0)", terminal, width)
	}
}

func TestPublicGuideTreeExcludesInternalCommandsAndRejectsAmbiguousAliases(t *testing.T) {
	t.Parallel()

	root := &cobra.Command{Use: "root"}
	visible := &cobra.Command{Use: "visible", Run: func(*cobra.Command, []string) {}}
	branch := &cobra.Command{Use: "branch"}
	branch.AddCommand(&cobra.Command{Use: "leaf", Run: func(*cobra.Command, []string) {}})
	hidden := &cobra.Command{Use: "hidden", Hidden: true, Run: func(*cobra.Command, []string) {}}
	deprecated := &cobra.Command{Use: "deprecated", Deprecated: "removed", Run: func(*cobra.Command, []string) {}}
	inert := &cobra.Command{Use: "inert"}
	aliasOne := &cobra.Command{Use: "alias-one", Aliases: []string{"shared"}, Run: func(*cobra.Command, []string) {}}
	aliasTwo := &cobra.Command{Use: "alias-two", Aliases: []string{"shared"}, Run: func(*cobra.Command, []string) {}}
	root.AddCommand(visible, branch, hidden, deprecated, inert, aliasOne, aliasTwo)

	children := publicGuideChildren(root)
	names := make([]string, 0, len(children))
	for _, child := range children {
		names = append(names, child.Name())
	}
	if want := []string{"alias-one", "alias-two", "branch", "visible"}; !slices.Equal(names, want) {
		t.Fatalf("public children = %q, want %q", names, want)
	}
	if got := guideCommandPath(root, root); got != "root" {
		t.Fatalf("root command path = %q, want root", got)
	}
	if got := guideCommandPath(root, branch); got != "root branch" {
		t.Fatalf("branch command path = %q, want root branch", got)
	}
	if _, err := resolveGuideTarget(root, []string{"shared"}); !errors.Is(err, errGuidePath) {
		t.Fatalf("ambiguous alias error = %v, want errGuidePath", err)
	}
}

func TestHelpPropagatesWriterFailure(t *testing.T) {
	t.Parallel()

	wantErr := errGuideWriter
	root := newGuideTestRoot(false, 0, nil)
	root.SetOut(guideFailingWriter{err: wantErr})
	root.SetErr(io.Discard)
	root.SetArgs([]string{"help", "--plain"})
	command, runErr := root.ExecuteC()
	err := errors.Join(runErr, closeCommandIO(command))
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want writer failure", err)
	}
}

func TestReferenceGuidePointerReportsWriterFailure(t *testing.T) {
	t.Parallel()

	root := initializedGuideRoot()
	root.SetOut(guideFailingWriter{err: errGuideWriter})
	var stderr bytes.Buffer
	root.SetErr(&stderr)
	target, err := resolveGuideTarget(root, []string{"net"})
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Help(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "write usage-guide pointer") || !strings.Contains(stderr.String(), errGuideWriter.Error()) {
		t.Fatalf("stderr = %q, want guide-pointer writer diagnostic", stderr.String())
	}
}

func TestDocumentedRootGuideKeyWorkflow(t *testing.T) {
	t.Parallel()

	privateKey := filepath.Join(t.TempDir(), "private.pem")
	if _, err := executeRoot(t, "key", "generate", "ed25519", "--output", privateKey); err != nil {
		t.Fatalf("documented generate command: %v", err)
	}
	output, err := executeRoot(t, "key", "inspect", "--input", privateKey)
	if err != nil {
		t.Fatalf("documented inspect command: %v", err)
	}
	if !strings.Contains(output, "Algorithm: ed25519") {
		t.Fatalf("inspection output = %q, want generated Ed25519 key metadata", output)
	}
}

func initializedGuideRoot() *cobra.Command {
	root := newGuideTestRoot(false, 0, nil)
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	return root
}

func newGuideTestRoot(terminal bool, width int, environment map[string]string) *cobra.Command {
	return newRootCmdWithGuideDependencies(defaultDNSDependencies(), guideDependencies{
		getenv: func(name string) (string, bool) {
			value, ok := environment[name]
			return value, ok
		},
		terminal: func(io.Writer) (bool, int) { return terminal, width },
	})
}

func publicGuidePaths(root *cobra.Command) []string {
	paths := []string{""}
	var visit func(*cobra.Command)
	visit = func(parent *cobra.Command) {
		for _, child := range publicGuideChildren(parent) {
			paths = append(paths, canonicalGuideKey(root, child))
			visit(child)
		}
	}
	visit(root)
	slices.Sort(paths)
	return paths
}

func guideHasBlock(blocks []guideBlock, kind guideBlockKind) bool {
	return slices.ContainsFunc(blocks, func(block guideBlock) bool { return block.kind == kind })
}

func sourceHasCommand(source []byte, command string) bool {
	return regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(command) + `$`).Match(source)
}

type guidePanicReader struct{}

func (guidePanicReader) Read([]byte) (int, error) {
	panic("guide command read operational stdin")
}

type guideFailingWriter struct{ err error }

func (writer guideFailingWriter) Write([]byte) (int, error) {
	return 0, writer.err
}

var _ io.Reader = guidePanicReader{}

var _ io.Writer = guideFailingWriter{}
