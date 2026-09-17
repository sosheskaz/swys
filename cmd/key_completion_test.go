package cmd

import (
	"slices"
	"strings"
	"testing"
)

func TestKeyCompletionDescriptionsAndContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		contains []string
		excludes []string
	}{
		{
			name: "algorithm descriptions",
			args: []string{"key", "generate", ""},
			contains: []string{
				"aes128\tAES-128 symmetric key",
				"aes-128\tAES-128 symmetric key",
				"ed25519\tEd25519 signing key",
				"ecdsa-p256\tECDSA key on NIST P-256",
			},
		},
		{
			name:     "public output first through aliases",
			args:     []string{"k", "g", "--public-out", "public.pem", ""},
			contains: []string{"ed25519\tEd25519 signing key", "rsa-4096\tRSA key with a 4096-bit modulus"},
			excludes: []string{"aes128\tAES-128 symmetric key", "aes-256\tAES-256 symmetric key"},
		},
		{
			name:     "public format first",
			args:     []string{"key", "generate", "--public-format", "openssh", ""},
			contains: []string{"p256\tECDSA key on NIST P-256"},
			excludes: []string{"aes192\tAES-192 symmetric key"},
		},
		{
			name:     "AES algorithm hides public flags",
			args:     []string{"key", "generate", "aes-256", "--"},
			contains: []string{"--output\tredirect stdout to this file"},
			excludes: []string{"--public-out\t", "--public-format\t"},
		},
		{
			name:     "asymmetric algorithm retains public flags",
			args:     []string{"key", "generate", "ed25519", "--"},
			contains: []string{"--public-out\twrite the corresponding public key to a file", "--public-format\tformat for --public-out"},
		},
		{
			name:     "AES explicit public format has no values",
			args:     []string{"key", "generate", "aes128", "--public-format", ""},
			excludes: []string{"openssh\t", "pkix-pem\t"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			lines := keyCompletionLines(t, test.args...)
			for _, want := range test.contains {
				if !slices.ContainsFunc(lines, func(line string) bool { return strings.HasPrefix(line, want) }) {
					t.Fatalf("completion lines = %q, want prefix %q", lines, want)
				}
			}
			for _, unwanted := range test.excludes {
				if slices.ContainsFunc(lines, func(line string) bool { return strings.HasPrefix(line, unwanted) }) {
					t.Fatalf("completion lines = %q, unwanted prefix %q", lines, unwanted)
				}
			}
			if lines[len(lines)-1] != ":4" {
				t.Fatalf("completion directive = %q, want :4", lines[len(lines)-1])
			}
		})
	}
}

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
		{"key", "generate", "ed25519", ""},
	} {
		lines := keyCompletionLines(t, path...)
		if lines[len(lines)-1] != ":4" {
			t.Fatalf("completion %q directive = %q, want :4", path, lines[len(lines)-1])
		}
	}

	for _, path := range [][]string{
		{"key", "public", "--input", ""},
		{"key", "public", "--output", ""},
		{"key", "generate", "--public-out", ""},
	} {
		lines := keyCompletionLines(t, path...)
		if lines[len(lines)-1] != ":0" {
			t.Fatalf("completion %q directive = %q, want :0", path, lines[len(lines)-1])
		}
	}
}

func TestKeyCompletionWithoutDescriptionsKeepsContextFiltering(t *testing.T) {
	t.Parallel()
	stdout, _, err := executeRootStreams(t, "__completeNoDesc", "key", "generate", "aes128", "--")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout, "--public-out") || strings.Contains(stdout, "--public-format") {
		t.Fatalf("AES flag completions = %q, want no public-output options", stdout)
	}
}

func keyCompletionLines(t *testing.T, args ...string) []string {
	t.Helper()
	stdout, _, err := executeRootStreams(t, append([]string{"__complete"}, args...)...)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(stdout), "\n")
}
