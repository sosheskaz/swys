package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
