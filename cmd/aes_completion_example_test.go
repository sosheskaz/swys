package cmd

import (
	"strings"
	"testing"
)

func TestAESCompletionExamples(t *testing.T) {
	t.Parallel()
	t.Run("describes cipher modes through an alias", func(t *testing.T) {
		t.Parallel()
		output := completeRoot(t, "aes", "enc", "--cipher-mode", "")
		assertCompletionLine(t, output, "gcm\tauthenticated default")
		assertCompletionLine(t, output, "cbc\tcompatibility mode")
		assertCompletionDirective(t, output, ":4")
	})

	t.Run("AAD restricts the mode to GCM", func(t *testing.T) {
		t.Parallel()
		output := completeRoot(t, "aes", "encrypt", "--aad=", "--cipher-mode", "")
		assertCompletionLine(t, output, "gcm\tauthenticated default")
		assertNoCompletionLine(t, output, "cbc\tcompatibility mode")
	})

	t.Run("IV restricts the mode to CBC", func(t *testing.T) {
		t.Parallel()
		output := completeRoot(t, "aes", "e", "--iv=", "--cipher-mode", "")
		assertCompletionLine(t, output, "cbc\tcompatibility mode")
		assertNoCompletionLine(t, output, "gcm\tauthenticated default")
	})
}

func completeRoot(t *testing.T, args ...string) string {
	t.Helper()
	output, _, err := executeRootStreams(t, append([]string{"__complete"}, args...)...)
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func assertCompletionLine(t *testing.T, output, want string) {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if line == want {
			return
		}
	}
	t.Fatalf("completion output %q does not contain line %q", output, want)
}

func assertNoCompletionLine(t *testing.T, output, unwanted string) {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if line == unwanted {
			t.Fatalf("completion output %q contains conflicting line %q", output, unwanted)
		}
	}
}

func assertCompletionDirective(t *testing.T, output, want string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if len(lines) == 0 || lines[len(lines)-1] != want {
		t.Fatalf("completion output %q has directive %q, want %q", output, lines[len(lines)-1], want)
	}
}
