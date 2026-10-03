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
	outputPath := filepath.Join(t.TempDir(), "npc.bash")
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
	assert.Contains(t, string(script), "# bash completion V2 for npc")
}

func TestExampleSharedPermissionCompletion(t *testing.T) {
	t.Parallel()
	output := executeSharedCompletion(t, "__complete", "aes", "keygen", "--mode", "06")
	for _, candidate := range []string{"0600\towner read/write", "0640\towner read/write and group read", "0644\towner read/write and group/world read"} {
		assert.Contains(t, output, candidate+"\n")
	}
	assert.True(t, strings.HasSuffix(output, ":4\n"), "completion = %q, want no file fallback", output)
}

func executeSharedCompletion(t *testing.T, args ...string) string {
	t.Helper()
	output, _, err := executeRootStreams(t, args...)
	require.NoError(t, err)
	return output
}
