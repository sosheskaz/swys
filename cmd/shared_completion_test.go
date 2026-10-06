package cmd

import (
	"bytes"
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
	assert.Equal(t, ":4\n", executeSharedCompletion(t, "__complete", "cert", "help", "--output", ""), "guides do not offer file completion")
	_, _, err := executeRootStreams(t, "http", "--follow", "--help")
	require.NoError(t, err, "bare boolean flag changed")
}

func TestSharedCompletionPreservesNativeFlagParsing(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		want string
		args []string
	}{
		{name: "pending long path", args: []string{"cert", "key-inspect", "--output", ""}, want: ":0\n"},
		{name: "pending short encoding", args: []string{"hash", "sha256", "-e", "h"}, want: "hex\n:4\n"},
		{name: "equals encoding", args: []string{"hash", "sha256", "--encoding=he"}, want: "hex\n:4\n"},
		{
			name: "flag-looking literal data",
			args: []string{"http", "--data", "--not-a-flag", "--follow="}, want: "true\nfalse\n:4\n",
		},
		{name: "literal separator", args: []string{"dns", "--", "example.test", "AA"}, want: "AAAA\n:4\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, test.want, executeSharedCompletion(t, append([]string{"__completeNoDesc"}, test.args...)...))
		})
	}
}

func TestSharedMalformedCompletionRestoresReusedRoot(t *testing.T) {
	t.Parallel()
	root := NewCommand()
	root.SetIn(guidePanicReader{})
	stdout, _, err := executeRootCommandStreams(t, root, "__complete", "http", "--follow=invalid", "")
	require.NoError(t, err)
	assert.Equal(t, ":4\n", stdout)
	stdout, _, err = executeRootCommandStreams(t, root, "__complete", "http", "--follow=")
	require.NoError(t, err)
	assert.Equal(t, "true\nfalse\n:4\n", stdout, "malformed-request handling must not replace later completion")
	freshHelp, _, err := executeRootStreams(t, "http", "--help")
	require.NoError(t, err)
	reusedHelp, _, err := executeRootCommandStreams(t, root, "http", "--help")
	require.NoError(t, err)
	assert.Equal(t, freshHelp, reusedHelp, "malformed completion must preserve ordinary help")
}

func TestSharedHashCompletionDoesNotOfferFiles(t *testing.T) {
	t.Parallel()
	assert.Equal(t, ":4\n", executeSharedCompletion(t, "__complete", "hash", "sha256", ""))
}

func TestSharedIOCapabilitiesRestoreHelpAndCompletion(t *testing.T) {
	t.Parallel()
	root := NewCommand()
	root.SetIn(guidePanicReader{})
	for _, test := range []struct {
		args         []string
		want, absent []string
	}{
		{args: []string{"aes", "keygen"}, want: []string{"--output", "--mode"}, absent: []string{"--input"}},
		{args: []string{"help"}, absent: []string{"--input", "--output", "--mode"}},
		{args: []string{"cert", "help"}, absent: []string{"--input", "--output", "--mode"}},
		{args: []string{"completion", "help"}, absent: []string{"--input", "--output", "--mode"}},
		{args: []string{"completion"}, want: []string{"--output", "--mode"}, absent: []string{"--input"}},
		{args: []string{"aes"}, want: []string{"--input", "--output"}},
		{want: []string{"--input", "--output"}},
		{args: []string{"cert", "create"}, want: []string{"--input", "--output"}},
		{args: []string{"net", "connect"}, want: []string{"--input", "--output", "--cert", "--udp", "--tls"}},
		{args: []string{"hash", "sha256"}, want: []string{"--input", "--output", "--mode"}},
	} {
		command, _, err := root.Find(test.args)
		require.NoError(t, err)
		var output bytes.Buffer
		root.SetOut(&output)
		require.NoError(t, command.Help())
		for _, flag := range test.want {
			assert.Contains(t, output.String(), flag, "reference %q", test.args)
		}
		for _, flag := range test.absent {
			assert.NotContains(t, output.String(), flag, "reference %q", test.args)
		}
	}
	for _, test := range []struct {
		args   []string
		want   string
		absent []string
	}{
		{args: []string{"aes", "keygen", "--i"}, absent: []string{"--input"}},
		{args: []string{"aes", "keygen", "--o"}, want: "--output"},
		{args: []string{"help", "--"}, absent: []string{"--input", "--output", "--mode"}},
		{args: []string{"cert", "help", "--"}, absent: []string{"--input", "--output", "--mode"}},
		{args: []string{"completion", "--i"}, absent: []string{"--input"}},
		{args: []string{"completion", "--o"}, want: "--output"},
		{args: []string{"hash", "sha256", "--i"}, want: "--input"},
	} {
		output, _, err := executeRootCommandStreams(t, root, append([]string{"__complete"}, test.args...)...)
		require.NoError(t, err)
		if test.want != "" {
			assert.Contains(t, output, test.want, "complete %q", test.args)
		}
		for _, flag := range test.absent {
			assert.NotContains(t, output, flag, "complete %q", test.args)
		}
	}
}
