package http_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExampleHTTPJSONFileCompletion(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	writeCompletionFixture(t, filepath.Join(directory, "payload.json"))
	writeCompletionFixture(t, filepath.Join(directory, "UPPER.JSON"))
	writeCompletionFixture(t, filepath.Join(directory, "notes.jsonl"))
	writeCompletionFixture(t, filepath.Join(directory, "encoded.txt"))
	require.NoError(t, os.Mkdir(filepath.Join(directory, "nested files"), 0o700))
	symlinkCreated := os.Symlink(filepath.Join(directory, "nested files"), filepath.Join(directory, "linked files")) == nil
	prefix := "@" + directory + string(filepath.Separator)

	values, directive := completeHTTPCommand(t, "--json", prefix)
	assertHTTPCompletions(t, values, prefix+"payload.json", prefix+"UPPER.JSON", prefix+"nested files/")
	if symlinkCreated {
		assertHTTPCompletions(t, values, prefix+"linked files/")
	}
	assertHTTPCompletionAbsent(t, values, prefix+"notes.jsonl", prefix+"encoded.txt")
	assertHTTPDirective(t, directive)
	stdinValues, _ := completeHTTPCommand(t, "--json", "@")
	assertHTTPCompletions(t, stdinValues, "@-")

	values, _ = completeHTTPCommand(t, "--input-encoding", "base64", "--json", prefix)
	assertHTTPCompletions(t, values, prefix+"encoded.txt", prefix+"notes.jsonl")

	values, directive = completeHTTPCommand(t, "--json", prefix+"payload.json")
	assertHTTPCompletions(t, values, prefix+"payload.json")
	assertHTTPDirectiveAllowsSpace(t, directive)
	values, directive = completeHTTPCommand(t, "--json", "@-")
	assertHTTPCompletions(t, values, "@-")
	assertHTTPDirectiveAllowsSpace(t, directive)
}

func TestExampleHTTPSelectionAndFormatCompletion(t *testing.T) {
	t.Parallel()
	values, directive := completeHTTPCommand(t, "--select", "")
	assertHTTPCompletions(t, values, "body", "response")
	assertHTTPDirectiveAllowsSpace(t, directive)

	values, _ = completeHTTPCommand(t, "--select", "body", "--format", "")
	assertHTTPCompletions(t, values, "raw", "json")
	assertHTTPCompletionAbsent(t, values, "text")

	values, _ = completeHTTPCommand(t, "--select", "response", "--format", "")
	assertHTTPCompletions(t, values, "text", "json")
	assertHTTPCompletionAbsent(t, values, "raw")
}

func TestExampleHTTPMultipartPathCompletion(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "report one.txt")
	writeCompletionFixture(t, path)
	require.NoError(t, os.Mkdir(filepath.Join(directory, "uploads"), 0o700))
	prefix := directory + string(filepath.Separator)

	values, directive := completeHTTPCommand(t, "--form", "name=demo", "--file", "attachment="+prefix)
	assertHTTPCompletions(t, values, "attachment="+path, "attachment="+prefix+"uploads/")
	assertHTTPDirective(t, directive)

	values, _ = completeHTTPCommand(t, "--file", "avatar="+path, "--file", "document="+prefix)
	assertHTTPCompletions(t, values, "document="+path)

	values, directive = completeHTTPCommand(t, "--file", "attachment="+path)
	assertHTTPCompletions(t, values, "attachment="+path)
	assertHTTPDirectiveAllowsSpace(t, directive)
}

func TestExampleHTTPHeaderCompletion(t *testing.T) {
	t.Parallel()

	values, directive := completeHTTPCommand(t, "-H", "auth")
	assertHTTPCompletions(t, values, "authorization: ")
	assertHTTPDirective(t, directive)

	values, directive = completeHTTPCommand(t, "-H", "Authorization:")
	assertHTTPCompletions(t, values, "Authorization:Bearer ", "Authorization:Basic ")
	assertHTTPDirective(t, directive)

	values, _ = completeHTTPCommand(t, "--header", "Accept-Encoding:gzip,")
	assertHTTPCompletions(t, values, "Accept-Encoding:gzip, identity")
	assertHTTPCompletionAbsent(t, values, "Accept-Encoding:gzip, gzip")

	values, _ = completeHTTPCommand(t, "-H", "Content-Type:multipart/")
	assertHTTPCompletions(t, values, "Content-Type:multipart/form-data")

	values, _ = completeHTTPCommand(t, "-H", "Cache-Control:max-age=60,")
	assertHTTPCompletionAbsent(t, values, "Cache-Control:max-age=60, max-age=")

	values, _ = completeHTTPCommand(t, "-H", "Accept-Encoding:i")
	assertHTTPCompletions(t, values, "Accept-Encoding:identity")
}

func TestHTTPAuthorizationCompletionWithoutDescriptionsDocumentsCobraLimitation(t *testing.T) {
	t.Parallel()

	stdout, _, err := executeRootStreams(t, "__completeNoDesc", "http", "--header", "Authorization:")
	require.NoError(t, err)
	want := "Authorization:Bearer\nAuthorization:Basic\n:6\n"
	if stdout != want {
		t.Fatalf("completion = %q, want Cobra to trim the authorization scheme spaces as %q", stdout, want)
	}
}

func TestHTTPGeneratedFishCompletionTraversesDirectoriesWithSpaces(t *testing.T) {
	t.Parallel()

	fish, err := exec.LookPath("fish")
	if err != nil {
		t.Skip("fish is not installed")
	}
	fixture := filepath.Join(t.TempDir(), "a b", "nested c")
	require.NoError(t, os.MkdirAll(fixture, 0o700))
	jsonPath := filepath.Join(fixture, "payload.json")
	writeCompletionFixture(t, jsonPath)
	spacedJSONPath := filepath.Join(fixture, "payload file.json")
	writeCompletionFixture(t, spacedJSONPath)
	spacedDirectory := filepath.Join(fixture, "directory with space")
	require.NoError(t, os.Mkdir(spacedDirectory, 0o700))
	fixtureRoot := filepath.Dir(filepath.Dir(fixture))
	literalCollision := fixtureRoot + string(filepath.Separator) + `a\ b`
	require.NoError(t, os.Mkdir(literalCollision, 0o700))
	literalCollisionPath := filepath.Join(literalCollision, "literal.json")
	writeCompletionFixture(t, literalCollisionPath)

	completionPath := filepath.Join(t.TempDir(), "npc.fish")
	generate := exec.CommandContext(
		t.Context(), os.Args[0], "-test.run=TestHTTPFishCompletionHelper", "--", "completion", "fish",
	)
	generate.Env = append(os.Environ(), "NPC_HTTP_COMPLETION_HELPER=1")
	generated, err := generate.Output()
	require.NoError(t, err, "generate Fish completion: %v", err)
	require.NoError(t, os.WriteFile(completionPath, generated, 0o600))

	escapedFixture := strings.ReplaceAll(fixture, " ", `\ `) + string(filepath.Separator)
	command := exec.CommandContext(t.Context(), fish, "-c", `
function npc
    env NPC_HTTP_COMPLETION_HELPER=1 $TEST_BINARY -test.run=TestHTTPFishCompletionHelper -- $argv
end
source $COMPLETION_SCRIPT
complete -C "npc http --json @$ESCAPED_FIXTURE"
complete -C "npc http --file attachment=$ESCAPED_FIXTURE"
complete -C "npc http --json @$ESCAPED_FILE_PREFIX"
complete -C "npc http --file attachment=$ESCAPED_FILE_PREFIX"
complete -C "npc http --json @$ESCAPED_DIRECTORY_PREFIX"
complete -C "npc http --json @$ESCAPED_PARENT"
complete -C "npc http --json @$ESCAPED_LITERAL"
complete -C "npc http --header Authorization:"
complete -C "npc net connect --tls --alpn h"
`)
	command.Env = append(os.Environ(),
		"TEST_BINARY="+os.Args[0],
		"COMPLETION_SCRIPT="+completionPath,
		"ESCAPED_FIXTURE="+escapedFixture,
		"ESCAPED_FILE_PREFIX="+escapedFixture+`payload\ f`,
		"ESCAPED_DIRECTORY_PREFIX="+escapedFixture+`directory\ w`,
		"ESCAPED_PARENT="+strings.ReplaceAll(filepath.Dir(fixture), " ", `\ `)+string(filepath.Separator),
		"ESCAPED_LITERAL="+strings.ReplaceAll(strings.ReplaceAll(literalCollision, `\`, `\\`), " ", `\ `)+string(filepath.Separator),
	)
	output, err := command.CombinedOutput()
	require.NoError(t, err, "generated Fish completion: %v\n%s", err, output)
	for _, want := range []string{"@" + jsonPath, "attachment=" + jsonPath} {
		if !strings.Contains(string(output), want) {
			t.Errorf("generated Fish completion = %q, missing %q", output, want)
		}
	}
	for _, want := range []string{
		"@" + spacedJSONPath,
		"attachment=" + spacedJSONPath,
		"@" + spacedDirectory + string(filepath.Separator),
		"@" + literalCollisionPath,
		"Authorization:Bearer ",
		"h2",
	} {
		if !strings.Contains(string(output), want) {
			t.Errorf("generated Fish completion = %q, missing basename completion %q", output, want)
		}
	}

	literalFixture := t.TempDir() + string(filepath.Separator) + `literal\ name`
	require.NoError(t, os.Mkdir(literalFixture, 0o700))
	literalJSONPath := filepath.Join(literalFixture, "payload.json")
	writeCompletionFixture(t, literalJSONPath)
	values, _ := completeHTTPCommand(t, "--json", "@"+literalFixture+string(filepath.Separator))
	assertHTTPCompletions(t, values, "@"+literalJSONPath)
}

func TestHTTPFishCompletionHelper(t *testing.T) {
	t.Parallel()

	if os.Getenv("NPC_HTTP_COMPLETION_HELPER") != "1" {
		return
	}
	separator := slices.Index(os.Args, "--")
	if separator < 0 {
		os.Exit(2)
	}
	command := newRootCmd()
	command.SetArgs(os.Args[separator+1:])
	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestHTTPCompletionSuppressesFilesAndInvalidOptions(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"https://example.test", ""},
		{"https://example.test", "extra", ""},
		{"--data", "literal", ""},
		{"--json", `{}`, ""},
		{"--header", "X-Custom: anything", ""},
		{"--form", "name=value", ""},
		{"--resolve", "example.test:443:192.0.2.1", ""},
		{"--servername", "example.test", ""},
		{"--connect-timeout", "1s", ""},
		{"--timeout", "2s", ""},
		{"--max-redirects", "3", ""},
	} {
		_, directive := completeHTTPCommand(t, args...)
		if directive&cobra.ShellCompDirectiveNoFileComp == 0 {
			t.Fatalf("completion for %q directive = %v, want no-file", args, directive)
		}
	}

	values, _ := completeHTTPCommand(t, "--json", `{}`, "-")
	for _, conflict := range []string{"--input", "--data", "--json", "--form", "--file"} {
		assertHTTPCompletionAbsent(t, values, conflict)
	}
	assertHTTPCompletions(t, values, "--header", "--input-encoding")

	values, _ = completeHTTPCommand(t, "--select", "response", "--format", "")
	assertHTTPCompletions(t, values, httpFormatText, httpFormatJSON)
	assertHTTPCompletionAbsent(t, values, "raw")

	values, _ = completeHTTPCommand(t, "--form", "name=value", "--file", "asset=missing", "--input-encoding", "")
	assertHTTPCompletions(t, values, httpEncodingRaw)
	assertHTTPCompletionAbsent(t, values, "base64")

	values, _ = completeHTTPCommand(t, "--format", "json", "-")
	assertHTTPCompletionAbsent(t, values, "--include")
	assertHTTPCompletions(t, values, "--select")
	values, _ = completeHTTPCommand(t, "--encoding", "base64", "--format", "")
	assertHTTPCompletions(t, values, "raw", httpFormatJSON)
	assertHTTPCompletionAbsent(t, values, httpFormatText)
	values, _ = completeHTTPCommand(t, "-X", http.MethodHead, "--encoding", "")
	assertHTTPCompletions(t, values, httpEncodingRaw, "base64")
	values, _ = completeHTTPCommand(t, "--encoding", "base64", "--method", "")
	assertHTTPCompletions(t, values, http.MethodHead)

	values, _ = completeHTTPCommand(t, "--stdin", httpStdinAlways, "-")
	for _, conflict := range []string{"--input", "--data", "--json", "--form", "--file"} {
		assertHTTPCompletionAbsent(t, values, conflict)
	}
	values, _ = completeHTTPCommand(t, "--stdin", httpStdinNever, "--json", "@")
	assertHTTPCompletionAbsent(t, values, "@-")
	values, _ = completeHTTPCommand(t, "--input-encoding", "base64", "-")
	assertHTTPCompletionAbsent(t, values, "--form", "--file")

	values, _ = completeHTTPCommand(t, "--file", "asset=missing", "-H", "C")
	assertHTTPCompletionAbsent(t, values, "Content-Type: ")
	values, _ = completeHTTPCommand(t, "-H", "Content-Type:multipart/form-data", "-")
	assertHTTPCompletionAbsent(t, values, "--file")
}

func TestHTTPCompletionDoesNotReadFilesOrMakeRequests(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "unreadable.json")
	writeCompletionFixture(t, path)
	require.NoError(t, os.Chmod(path, 0))
	t.Cleanup(func() {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Errorf("restore fixture permissions: %v", err)
		}
	})

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(server.Close)
	values, _ := completeHTTPCommand(t, server.URL, "--json", "@"+path)
	assertHTTPCompletions(t, values, "@"+path)
	if requests.Load() != 0 {
		t.Fatal("completion made a network request")
	}
}

func completeHTTPCommand(t *testing.T, args ...string) ([]string, cobra.ShellCompDirective) {
	t.Helper()
	commandArgs := append([]string{"__complete", "http"}, args...)
	stdout, _, err := executeRootStreams(t, commandArgs...)
	require.NoError(t, err, "complete %q: %v", args, err)
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[len(lines)-1], ":") {
		t.Fatalf("completion output = %q, missing directive", stdout)
	}
	directiveText := strings.TrimPrefix(lines[len(lines)-1], ":")
	var directive cobra.ShellCompDirective
	for _, char := range directiveText {
		if char < '0' || char > '9' {
			t.Fatalf("completion directive = %q", directiveText)
		}
		directive = directive*10 + cobra.ShellCompDirective(char-'0')
	}
	return lines[:len(lines)-1], directive
}

func assertHTTPCompletions(t *testing.T, values []string, wanted ...string) {
	t.Helper()
	for _, want := range wanted {
		if !containsHTTPCompletion(values, want) {
			t.Errorf("completion = %q, missing %q", values, want)
		}
	}
}

func assertHTTPCompletionAbsent(t *testing.T, values []string, unwanted ...string) {
	t.Helper()
	for _, value := range unwanted {
		if containsHTTPCompletion(values, value) {
			t.Errorf("completion = %q, unexpectedly contains %q", values, value)
		}
	}
}

func containsHTTPCompletion(values []string, want string) bool {
	for _, value := range values {
		candidate, _, _ := strings.Cut(value, "\t")
		if candidate == want {
			return true
		}
	}
	return false
}

func assertHTTPDirective(t *testing.T, got cobra.ShellCompDirective) {
	t.Helper()
	want := cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	if got != want {
		t.Fatalf("completion directive = %v, want %v", got, want)
	}
}

func assertHTTPDirectiveAllowsSpace(t *testing.T, got cobra.ShellCompDirective) {
	t.Helper()
	if got&cobra.ShellCompDirectiveNoFileComp == 0 || got&cobra.ShellCompDirectiveNoSpace != 0 {
		t.Fatalf("completion directive = %v, want no-file and an argument separator", got)
	}
}

func writeCompletionFixture(t *testing.T, name string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Clean(name), []byte("completion must not read this content"), 0o600))
}

func TestHTTPTLSArtifactEncodingCompletion(t *testing.T) {
	t.Parallel()
	for _, source := range []string{"ca", "cert", "key"} {
		values, directive := completeHTTPCommand(t, "--"+source+"-encoding", "ba")
		assert.Empty(t, values)
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
		values, directive = completeHTTPCommand(t, "--"+source, "missing", "--"+source+"-encoding", "ba")
		assertHTTPCompletions(t, values, "base64", "base32")
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
		_, directive = completeHTTPCommand(t, "--"+source, "")
		assert.Zero(t, directive&cobra.ShellCompDirectiveNoFileComp, "credential paths retain filename fallback")
	}
}
