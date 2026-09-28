package cmd

import (
	"strings"
	"testing"
)

func TestSharedEncodingAndFormatDescriptions(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		want string
		args []string
	}{
		{args: []string{"aes", "encrypt", "--encoding", ""}, want: "base64\tstandard Base64 with padding"},
		{args: []string{"aes", "decrypt", "--input-encoding", ""}, want: "base64url\tURL-safe Base64 (unpadded output)"},
		{args: []string{"http", "--encoding", ""}, want: "hex\thexadecimal"},
		{args: []string{"http", "--input-encoding", ""}, want: "b64\talias for base64"},
		{args: []string{"http", "--format", ""}, want: "json\tstructured JSON"},
		{args: []string{"dns", "--format", ""}, want: "json\tstructured JSON"},
		{args: []string{"certificate", "inspect", "-f", ""}, want: "chain\tissuer certificates as PEM, excluding the leaf"},
		{args: []string{"cert", "key-inspect", "--format", ""}, want: "text\thuman-readable text"},
		{args: []string{"nc", "connect", "tcp", "-e", ""}, want: "raw\tunencoded bytes"},
	} {
		output := executeSharedCompletion(t, append([]string{"__complete"}, test.args...)...)
		if !strings.Contains(output, test.want+"\n") || !strings.HasSuffix(output, ":4\n") {
			t.Errorf("complete %q = %q, want described %q and no files", test.args, output, test.want)
		}
		plain := executeSharedCompletion(t, append([]string{"__completeNoDesc"}, test.args...)...)
		if strings.Contains(plain, "\t") {
			t.Errorf("description-free completion contains descriptions: %q", plain)
		}
	}
}

func TestSharedBooleanValuesAndPrefixes(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"http", "--follow="},
		{"dns", "--reverse="},
		{"cert", "create", "--ca="},
		{"net", "connect", "--tls", "--insecure="},
		{"cert", "key-inspect", "--help="},
		{"completion", "bash", "--no-descriptions="},
		{"completion", "fish", "--help="},
		{"--version="},
		{"--help="},
	} {
		output := executeSharedCompletion(t, append([]string{"__complete"}, args...)...)
		if output != "true\nfalse\n:4\n" {
			t.Errorf("complete %q = %q, want true/false without files", args, output)
		}
	}
	if got := executeSharedCompletion(t, "__complete", "http", "--follow=f"); got != "false\n:4\n" {
		t.Fatalf("boolean prefix completion = %q", got)
	}
}

func TestSharedCompletionPreservesPathsAndManualModes(t *testing.T) {
	t.Parallel()
	for _, flag := range []string{"--input", "--output"} {
		output := executeSharedCompletion(t, "__complete", "cert", "key-inspect", flag, "")
		if output != ":0\n" {
			t.Errorf("%s completion = %q, want filesystem fallback", flag, output)
		}
	}
	if output := executeSharedCompletion(t, "__complete", "http", "--mode", "075"); output != ":4\n" {
		t.Fatalf("manual mode completion = %q, want no suggested restriction or files", output)
	}
	if _, _, err := executeRootStreams(t, "http", "--follow", "--help"); err != nil {
		t.Fatalf("bare boolean flag changed: %v", err)
	}
}
