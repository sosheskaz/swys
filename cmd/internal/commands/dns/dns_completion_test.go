package dns_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDNSCompletionRecordTypesFollowResolverContext(t *testing.T) {
	t.Parallel()

	directTypes := directDNSRecordTypes()
	for _, rejected := range []string{"AXFR", "IXFR"} {
		assert.NotContains(t, directTypes, rejected, "direct completions")
	}
	for record, recordType := range dns.StringToType {
		want := recordType != dns.TypeAXFR && recordType != dns.TypeIXFR
		assert.Equal(t, want, slices.Contains(directTypes, record), "direct completion membership for %s", record)
	}

	tests := []struct {
		name string
		args []string
		want []string
	}{
		{name: "system", args: []string{"dns", "example.test", ""}, want: []string{"A", "AAAA", "PTR"}},
		{name: "lowercase prefix", args: []string{"dns", "example.test", "a"}, want: []string{"A", "AAAA"}},
		{name: "direct resolver", args: []string{"dns", "--resolver", "dns", "example.test", ""}, want: directTypes},
		{name: "explicit UDP endpoint", args: []string{"dns", "@udp://192.0.2.53", "example.test", ""}, want: directTypes},
		{name: "explicit default port long", args: []string{"dns", "--port", "53", "example.test", ""}, want: directTypes},
		{name: "explicit default port short", args: []string{"dns", "-p", "53", "example.test", ""}, want: directTypes},
		{name: "server", args: []string{"dns", "@192.0.2.53", "example.test", ""}, want: directTypes},
		{name: "reverse long", args: []string{"dns", "--reverse", "192.0.2.10", ""}, want: []string{"PTR"}},
		{name: "reverse short direct", args: []string{"dns", "-x", "@192.0.2.53", "192.0.2.10", "p"}, want: []string{"PTR"}},
		{name: "dig alias", args: []string{"dig", "example.test", "AA"}, want: []string{"AAAA"}},
		{name: "nslookup alias", args: []string{"nslookup", "@192.0.2.53", "example.test", "CA"}, want: []string{"CAA"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, directive := executeDNSCompletion(t, test.args...)
			if !slices.Equal(got, test.want) {
				t.Fatalf("completions = %q, want %q", got, test.want)
			}
			assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
		})
	}
}

func TestDNSCompletionSuppressesFileFallback(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"dns", ""},
		{"dns", "@"},
		{"dns", "@192.0.2.53", ""},
		{"dns", "example.test", "A", ""},
		{"dns", "@192.0.2.53", "example.test", "A", ""},
		{"dns", "--port", ""},
		{"dns", "-p", ""},
		{"dns", "--timeout", ""},
		{"dns", "--servername", ""},
		{"dns", "@tcp://192.0.2.53", "--ca", ""},
	} {
		values, directive := executeDNSCompletion(t, args...)
		assert.Empty(t, values, "complete %q", args)
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive, "complete %q", args)
	}
}

func TestDNSCompletionOffersOnlyMeaningfulInheritedFileFlags(t *testing.T) {
	t.Parallel()
	values, directive := executeDNSCompletion(t, "dns", "--output", "")
	assert.Empty(t, values)
	assert.Equal(t, cobra.ShellCompDirectiveDefault, directive, "output filesystem fallback")
	values, directive = executeDNSCompletion(t, "dns", "--i")
	assert.NotContains(t, strings.Join(values, "\n"), "--input")
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
}

func TestDNSCompletionFiltersResolverConflicts(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"dns", "@192.0.2.53", "--resolver", ""},
		{"dns", "@tcp://192.0.2.53", "--resolver", ""},
		{"dns", "-p", "53", "--resolver", ""},
	} {
		values, directive := executeDNSCompletion(t, args...)
		assert.Equal(t, []string{"dns"}, values, "complete %q", args)
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive, "complete %q", args)
	}

	values, directive := executeDNSCompletion(t, "dns", "--resolver", "system", "--")
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive, "flag directive")
	joined := strings.Join(values, "\n")
	for _, conflict := range []string{"--port", "-p"} {
		assert.NotContains(t, joined, conflict, "flags after --resolver system")
	}
	for _, compatible := range []string{"--format", "--select", "--encoding", "--reverse", "--timeout"} {
		assert.Contains(t, joined, compatible, "flags after --resolver system")
	}
	assert.NotContains(t, joined, "--short", "removed flag")

	for _, test := range []struct {
		endpoint string
		wantTLS  bool
	}{
		{endpoint: "@udp://192.0.2.53"},
		{endpoint: "@tcp://192.0.2.53"},
		{endpoint: "@192.0.2.53"},
		{endpoint: "example.test"},
		{endpoint: "@tls://resolver.example", wantTLS: true},
		{wantTLS: true},
	} {
		args := []string{"dns"}
		if test.endpoint != "" {
			args = append(args, test.endpoint)
		}
		args = append(args, "--")
		candidates, flagDirective := executeDNSCompletion(t, args...)
		for _, flag := range []string{"--ca", "--system-ca", "--servername", "--cert", "--key", "--insecure"} {
			assert.Equal(t, test.wantTLS, slices.Contains(candidates, flag), "TLS flag %s after %q: %q", flag, args, candidates)
		}
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, flagDirective)
	}
}

func TestDNSCompletionFiltersEncryptedTrustValues(t *testing.T) {
	t.Parallel()
	caPath := filepath.Join(t.TempDir(), "trust.pem")
	require.NoError(t, os.WriteFile(caPath, []byte("completion must not parse credential contents"), 0))
	for _, test := range []struct {
		name string
		args []string
		want []string
	}{
		{name: "insecure blocks typed CA", args: []string{"@tls://resolver.example", "--insecure", "--ca", caPath}},
		{
			name: "CA constrains prospective insecure replacement",
			args: []string{"@https://resolver.example/dns-query", "--ca", caPath, "--insecure", "--insecure="},
			want: []string{"false"},
		},
		{
			name: "insecure excludes system CA true", args: []string{"@tls://resolver.example", "--insecure", "--system-ca="},
			want: []string{"false"},
		},
		{
			name: "last false permits system CA before partner",
			args: []string{"@https://resolver.example/dns-query", "--insecure", "--insecure=false", "--system-ca="},
			want: []string{"true", "false"},
		},
		{
			name: "empty CA permits insecure values", args: []string{"@tls://resolver.example", "--ca", "", "--insecure="},
			want: []string{"true", "false"},
		},
		{name: "plaintext excludes even false", args: []string{"@udp://192.0.2.53", "--insecure="}},
		{name: "name first excludes encrypted trust values", args: []string{"example.test", "--insecure="}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := append([]string{"dns"}, test.args...)
			values, directive := executeDNSRootCompletion(t, newRootCmd(), args...)
			if len(test.want) == 0 {
				assert.Empty(t, values)
			} else {
				assert.Equal(t, test.want, values)
			}
			assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
		})
	}
}

func TestDNSOutputOptionCompletion(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		flag string
		want []string
	}{
		{flag: "--select", want: []string{"result", "values"}},
		{flag: "--format", want: []string{"text", "json"}},
	} {
		values, directive := executeDNSCompletion(t, "dns", test.flag, "")
		assert.ElementsMatch(t, test.want, values, "complete %s", test.flag)
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive, "complete %s", test.flag)
	}
	values, directive := executeDNSCompletion(t, "dns", "--encoding", "bas")
	assert.Contains(t, values, "base64")
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
}

func TestDNSCompletionConflictHasNoRecordCandidates(t *testing.T) {
	t.Parallel()
	values, directive := executeDNSCompletion(t, "dns", "--resolver", "system", "--port", "53", "example.test", "")
	assert.Empty(t, values, "conflicting completion candidates")
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive, "conflicting completion directive")
}

func TestDNSCompletionEndpointSelectionFollowsFinalResolver(t *testing.T) {
	t.Parallel()
	directTypes := directDNSRecordTypes()
	for _, test := range []struct {
		resolverArgs []string
		want         []string
	}{
		{resolverArgs: []string{"--resolver", "system"}},
		{resolverArgs: []string{"--resolver", "dns", "--resolver", "system"}},
		{resolverArgs: []string{"--resolver", "system", "--resolver", "dns"}, want: directTypes},
	} {
		args := append([]string{"dns"}, test.resolverArgs...)
		args = append(args, "@udp://192.0.2.53", "example.test", "")
		values, directive := executeDNSCompletion(t, args...)
		if !slices.Equal(values, test.want) || directive != cobra.ShellCompDirectiveNoFileComp {
			t.Errorf("complete %q = %q, %v; want %q and no files", args, values, directive, test.want)
		}
	}
}

func TestDNSRejectsRemovedTransportFlag(t *testing.T) {
	t.Parallel()

	_, _, err := executeRootStreams(t, "dns", "example.test", "--transport", "udp")
	require.ErrorContains(t, err, "unknown flag: --transport")
}

func TestDNSCompletionFlagsFollowFinalResolver(t *testing.T) {
	t.Parallel()
	for _, resolvers := range [][]string{{"system", "dns"}, {"dns", "system"}} {
		values, _ := executeDNSCompletion(t, "dns", "--resolver", resolvers[0], "--resolver", resolvers[1], "--")
		joined := strings.Join(values, "\n")
		assert.Equal(t, resolvers[1] == "dns", strings.Contains(joined, "--port"), "flags after resolvers %q", resolvers)
		assert.NotContains(t, joined, "--transport", "flags after resolvers %q", resolvers)
	}
}

func TestDNSTLSArtifactEncodingCompletion(t *testing.T) {
	t.Parallel()
	values, directive := executeDNSCompletion(t, "dns", "example.com", "@tls://localhost", "--ca", "x", "--ca-encoding", "")
	assert.Empty(t, values, "an encrypted endpoint after the query name is not a valid direct DNS selector")
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)

	for _, source := range []string{"ca", "cert", "key"} {
		values, directive = executeDNSCompletion(t, "dns", "@tls://localhost", "--"+source+"-encoding", "ba")
		assert.Empty(t, values)
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
		values, directive = executeDNSCompletion(t, "dns", "@tls://localhost", "--"+source, "missing", "--"+source+"-encoding", "ba")
		candidates := strings.Join(values, "\n")
		assert.Contains(t, candidates, "base64")
		assert.Contains(t, candidates, "base32")
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
		values, directive = executeDNSCompletion(t, "dns", "@udp://localhost", "--"+source, "missing", "--"+source+"-encoding", "ba")
		assert.Empty(t, values)
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
	}
}

func TestDNSCompletionPreservesReusedRootReferenceHelp(t *testing.T) {
	t.Parallel()
	helpArgs := []string{"dns", "--resolver", "system", "--help"}
	freshHelp, _, err := executeRootStreams(t, helpArgs...)
	require.NoError(t, err)
	root := newRootCmd()
	_, _, err = executeRootCommandStreams(t, root, "__complete", "dns", "--resolver", "system", "--")
	require.NoError(t, err)
	reusedHelp, _, err := executeRootCommandStreams(t, root, helpArgs...)
	require.NoError(t, err)
	assert.Equal(t, freshHelp, reusedHelp, "completion must preserve the full reference help on later executions")
}
