package key_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyTargetCompletionDescriptions(t *testing.T) {
	t.Parallel()

	public := keyCompletionLines(t, "key", "public", "--to", "")
	for _, want := range []string{
		"openssh\tOpenSSH public key",
		"pkix-der\tPKIX public key in binary DER",
		"pkix-pem\tPKIX public key in PEM",
	} {
		if !slices.Contains(public, want) {
			t.Fatalf("public target completions = %q, want %q", public, want)
		}
	}

	convert := keyCompletionLines(t, "key", "convert", "--to", "")
	for _, want := range []string{
		"pkcs8-pem\tPKCS #8 private key in PEM",
		"sec1-der\tSEC 1 EC private key in binary DER",
	} {
		if !slices.Contains(convert, want) {
			t.Fatalf("conversion target completions = %q, want %q", convert, want)
		}
	}
}

func TestKeyCompletionFileDirectives(t *testing.T) {
	t.Parallel()

	for _, path := range [][]string{
		{"key", "public", ""},
		{"k", "i", ""},
		{"key", "convert", ""},
	} {
		lines := keyCompletionLines(t, path...)
		if lines[len(lines)-1] != ":4" {
			t.Fatalf("completion %q directive = %q, want :4", path, lines[len(lines)-1])
		}
	}

	for _, path := range [][]string{
		{"key", "public", "--input", ""},
		{"key", "public", "--output", ""},
	} {
		lines := keyCompletionLines(t, path...)
		if lines[len(lines)-1] != ":0" {
			t.Fatalf("completion %q directive = %q, want :0", path, lines[len(lines)-1])
		}
	}
}

func keyCompletionLines(t *testing.T, args ...string) []string {
	t.Helper()
	stdout, _, err := executeRootStreams(t, append([]string{"__complete"}, args...)...)
	require.NoError(t, err)
	return strings.Split(strings.TrimSpace(stdout), "\n")
}
