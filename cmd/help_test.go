package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/help"
)

var (
	errGuideTargetPreRun = errors.New("target pre-run executed")
	errGuideTargetRun    = errors.New("target handler executed")
	errGuideWriter       = errors.New("guide writer failed")
)

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
			stdout, stderr, err := executeRootCommandStreams(t, newGuideTestRoot(), args...)
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
			stdout, _, err := executeRootCommandStreams(t, newGuideTestRoot(), test.args...)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want diagnostic containing %q", err, test.wantErr)
			}
			if stdout != "" {
				t.Fatalf("stdout = %q, want no fallback guide", stdout)
			}
		})
	}
}

func TestHelpDoesNotRunTargetHooksOrHandlers(t *testing.T) {
	t.Parallel()

	root := newGuideTestRoot()
	target, _, err := root.Find([]string{"cert", "connect"})
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

	stdout, _, err := executeRootCommandStreams(t, newGuideTestRoot(), "net", "connect", "--tls")
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

func TestHelpCompletesCanonicalCommandPaths(t *testing.T) {
	t.Parallel()

	root := initializedGuideRoot()
	helpCmd, _, err := root.Find([]string{"help"})
	if err != nil {
		t.Fatal(err)
	}
	completions, directive := helpCmd.ValidArgsFunction(helpCmd, []string{"x509"}, "c")
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("directive = %v, want no file completion", directive)
	}
	hasConnect := slices.ContainsFunc(completions, func(completion cobra.Completion) bool {
		return strings.HasPrefix(completion, "connect")
	})
	if !hasConnect {
		t.Fatalf("completions = %q, want canonical connect path", completions)
	}
	completions, _ = helpCmd.ValidArgsFunction(helpCmd, nil, "x")
	hasCert := slices.ContainsFunc(completions, func(completion cobra.Completion) bool {
		return strings.HasPrefix(completion, "cert")
	})
	if !hasCert {
		t.Fatalf("alias completions = %q, want canonical cert path", completions)
	}
}

func TestHelpPropagatesWriterFailure(t *testing.T) {
	t.Parallel()

	wantErr := errGuideWriter
	root := newGuideTestRoot()
	root.SetOut(guideFailingWriter{err: wantErr})
	root.SetErr(io.Discard)
	root.SetArgs([]string{"help", "--plain"})
	command, runErr := root.ExecuteC()
	err := errors.Join(runErr, commandio.Close(command))
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
	target, _, err := root.Find([]string{"net"})
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
		t.Fatalf("documented generate Command: %v", err)
	}
	output, err := executeRoot(t, "key", "inspect", "--input", privateKey)
	if err != nil {
		t.Fatalf("documented inspect Command: %v", err)
	}
	if !strings.Contains(output, "Algorithm: ed25519") {
		t.Fatalf("inspection output = %q, want generated Ed25519 key metadata", output)
	}
}

func initializedGuideRoot() *cobra.Command {
	root := newGuideTestRoot()
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	return root
}

func newGuideTestRoot() *cobra.Command {
	return newRootCmdWithGuideDependencies(defaultDNSDependencies(), help.Dependencies{
		Getenv: func(_ string) (string, bool) {
			return "", false
		},
		Terminal: func(io.Writer) (bool, int) { return false, 0 },
	})
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

func TestRootGuideHighlightsCommandKeywords(t *testing.T) {
	t.Parallel()

	output, _, err := executeRootCommandStreams(t, newGuideTestRoot(), "help", "--rich")
	require.NoError(t, err)
	for _, keyword := range []string{"dns", "http", "net", "cert", "key", "aes", "hash"} {
		assert.Contains(t, output, "• \x1b[1m"+keyword+"\x1b[0m ", "command keyword %q styling", keyword)
	}
}
