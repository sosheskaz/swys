package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExampleBashCompletionWritesFile(t *testing.T) {
	t.Parallel()
	outputPath := filepath.Join(t.TempDir(), "swys.bash")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	process := newNetPipeProcess(ctx, "completion", "bash", "--output", outputPath)
	var stdout, stderr bytes.Buffer
	process.Stdout = &stdout
	process.Stderr = &stderr
	require.NoError(t, process.Run(), "generate Bash completion; stderr: %s", stderr.String())
	assert.Empty(t, stdout.Bytes(), "completion script leaked to stdout")
	assert.Empty(t, stderr.String())
	script, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.Contains(t, string(script), "# bash completion V2 for swys")
}

func TestExampleSharedPermissionCompletion(t *testing.T) {
	t.Parallel()
	output := executeSharedCompletion(t, "__complete", "aes", "keygen", "--mode", "06")
	for _, candidate := range []string{"0600\towner read/write", "0640\towner read/write and group read", "0644\towner read/write and group/world read"} {
		assert.Contains(t, output, candidate+"\n")
	}
	assert.True(t, strings.HasSuffix(output, ":4\n"), "completion = %q, want no file fallback", output)
}

func TestSharedMalformedCompletionRequestsAreQuiet(t *testing.T) {
	t.Parallel()
	const marker = "SWYS_INERT_COMPLETION_MARKER"
	const debugSentinel = "debug sentinel\n"
	for _, test := range []struct {
		name     string
		args     []string
		trailing []string
	}{
		{
			name:     "typed flag error",
			args:     []string{"__complete", "http", "--header", "X-SwYS-Test: " + marker},
			trailing: []string{"--follow=not-a-boolean"},
		},
		{
			name: "unknown completed flag",
			args: []string{"__completeNoDesc", "hash", "sha256"}, trailing: []string{"--unknown=" + marker},
		},
		{
			name:     "missing value before pending input",
			args:     []string{"__complete", "grpc", "127.0.0.1:1", "--header", "X-SwYS-Test: " + marker},
			trailing: []string{"--list", "--input"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			directory := t.TempDir()
			outputPath := filepath.Join(directory, "output")
			debugPath := filepath.Join(directory, "completion-debug")
			require.NoError(t, os.WriteFile(outputPath, []byte("preserve"), 0o600))
			require.NoError(t, os.WriteFile(debugPath, []byte(debugSentinel), 0o600))
			args := append([]string{}, test.args...)
			args = append(args, "--input", filepath.Join(directory, "missing"), "--output", outputPath)
			args = append(args, test.trailing...)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			process := newNetPipeProcess(ctx, append(args, "")...)
			process.Env = append(process.Env, "BASH_COMP_DEBUG_FILE="+debugPath)
			var stdout, stderr bytes.Buffer
			process.Stdout = &stdout
			process.Stderr = &stderr
			require.NoError(t, process.Run(), "completion process; stderr: %s", stderr.String())
			assert.Equal(t, ":4\n", stdout.String(), "malformed completion must suppress filesystem fallback")
			assert.Empty(t, stderr.String(), "malformed completion must not emit OS stderr diagnostics")
			debug, err := os.ReadFile(debugPath)
			require.NoError(t, err)
			assert.Equal(t, debugSentinel, string(debug), "malformed completion must not append arguments to debug logs")
			contents, err := os.ReadFile(outputPath)
			require.NoError(t, err)
			assert.Equal(t, []byte("preserve"), contents)
		})
	}
}

func executeSharedCompletion(t *testing.T, args ...string) string {
	t.Helper()
	output, _, err := executeRootStreams(t, args...)
	require.NoError(t, err)
	return output
}
