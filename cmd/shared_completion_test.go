package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		{args: []string{"certificate", "inspect", "-f", ""}, want: "pem\tcertificate PEM"},
		{args: []string{"certificate", "inspect", "--select", ""}, want: "chain\tsupplied certificates after the leaf"},
		{args: []string{"cert", "connect", "--select", "0"}, want: "0\troot of an unambiguous complete chain"},
		{args: []string{"cert", "key-inspect", "--format", ""}, want: "text\thuman-readable text"},
		{args: []string{"nc", "connect", "tcp", "-e", ""}, want: "raw\tunencoded bytes"},
	} {
		output := executeSharedCompletion(t, append([]string{"__complete"}, test.args...)...)
		assert.Contains(t, output, test.want+"\n", "complete %q", test.args)
		assert.True(t, strings.HasSuffix(output, ":4\n"), "complete %q = %q, want no files", test.args, output)
		plain := executeSharedCompletion(t, append([]string{"__completeNoDesc"}, test.args...)...)
		assert.NotContains(t, plain, "\t", "description-free completion")
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
		assert.Equal(t, "true\nfalse\n:4\n", output, "complete %q", args)
	}
	assert.Equal(t, "false\n:4\n", executeSharedCompletion(t, "__complete", "http", "--follow=f"), "boolean prefix completion")
}

func TestSharedCompletionPreservesPathsAndManualModes(t *testing.T) {
	t.Parallel()
	for _, flag := range []string{"--input", "--output"} {
		output := executeSharedCompletion(t, "__complete", "cert", "key-inspect", flag, "")
		assert.Equal(t, ":0\n", output, "%s filesystem fallback", flag)
	}
	assert.Equal(t, ":4\n", executeSharedCompletion(t, "__complete", "http", "--mode", "075"), "manual mode completion")
	_, _, err := executeRootStreams(t, "http", "--follow", "--help")
	require.NoError(t, err, "bare boolean flag changed")
}
