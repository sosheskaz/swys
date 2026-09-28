package dns_test

import (
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
	} {
		values, directive := executeDNSCompletion(t, args...)
		assert.Empty(t, values, "complete %q", args)
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive, "complete %q", args)
	}
}

func TestDNSCompletionPreservesInheritedFileCompletion(t *testing.T) {
	t.Parallel()
	for _, flag := range []string{"--input", "--output"} {
		values, directive := executeDNSCompletion(t, "dns", flag, "")
		assert.Empty(t, values, "complete %s", flag)
		assert.Equal(t, cobra.ShellCompDirectiveDefault, directive, "complete %s", flag)
	}
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
	for _, compatible := range []string{"--format", "--short", "--reverse", "--timeout"} {
		assert.Contains(t, joined, compatible, "flags after --resolver system")
	}
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
