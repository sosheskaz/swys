package cmd

import (
	"strings"
	"testing"
)

func TestExampleSharedPermissionCompletion(t *testing.T) {
	t.Parallel()
	output := executeSharedCompletion(t, "__complete", "key", "generate", "aes256", "--mode", "06")
	for _, candidate := range []string{"0600\towner read/write", "0640\towner read/write and group read", "0644\towner read/write and group/world read"} {
		if !strings.Contains(output, candidate+"\n") {
			t.Errorf("completion = %q, want %q", output, candidate)
		}
	}
	if !strings.HasSuffix(output, ":4\n") {
		t.Fatalf("completion = %q, want no file fallback", output)
	}
}

func executeSharedCompletion(t *testing.T, args ...string) string {
	t.Helper()
	output, _, err := executeRootStreams(t, args...)
	if err != nil {
		t.Fatal(err)
	}
	return output
}
