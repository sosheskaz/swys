package dns_test

import (
	"slices"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/spf13/cobra"
)

func TestDNSCompletionRecordTypesFollowResolverContext(t *testing.T) {
	t.Parallel()

	directTypes := directDNSRecordTypes()
	for _, rejected := range []string{"AXFR", "IXFR"} {
		if slices.Contains(directTypes, rejected) {
			t.Fatalf("direct completions contain rejected type %s", rejected)
		}
	}
	for record, recordType := range dns.StringToType {
		want := recordType != dns.TypeAXFR && recordType != dns.TypeIXFR
		if slices.Contains(directTypes, record) != want {
			t.Fatalf("direct completion membership for %s does not match parser registry", record)
		}
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
			if directive != cobra.ShellCompDirectiveNoFileComp {
				t.Fatalf("directive = %v, want no file completion", directive)
			}
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
		if len(values) != 0 {
			t.Errorf("complete %q = %q, want no values", args, values)
		}
		if directive != cobra.ShellCompDirectiveNoFileComp {
			t.Errorf("complete %q directive = %v, want no file completion", args, directive)
		}
	}
}

func TestDNSCompletionPreservesInheritedFileCompletion(t *testing.T) {
	t.Parallel()
	for _, flag := range []string{"--input", "--output"} {
		values, directive := executeDNSCompletion(t, "dns", flag, "")
		if len(values) != 0 || directive != cobra.ShellCompDirectiveDefault {
			t.Errorf("complete %s = %q, %v; want inherited file completion", flag, values, directive)
		}
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
		if !slices.Equal(values, []string{"dns"}) || directive != cobra.ShellCompDirectiveNoFileComp {
			t.Errorf("complete %q = %q, %v; want dns only and no files", args, values, directive)
		}
	}

	values, directive := executeDNSCompletion(t, "dns", "--resolver", "system", "--")
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("flag directive = %v, want no file completion", directive)
	}
	joined := strings.Join(values, "\n")
	for _, conflict := range []string{"--port", "-p"} {
		if strings.Contains(joined, conflict) {
			t.Errorf("flags after --resolver system contain %s: %q", conflict, values)
		}
	}
	for _, compatible := range []string{"--format", "--short", "--reverse", "--timeout"} {
		if !strings.Contains(joined, compatible) {
			t.Errorf("flags after --resolver system omit compatible %s: %q", compatible, values)
		}
	}
}

func TestDNSCompletionConflictHasNoRecordCandidates(t *testing.T) {
	t.Parallel()
	values, directive := executeDNSCompletion(t, "dns", "--resolver", "system", "--port", "53", "example.test", "")
	if len(values) != 0 || directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("conflicting completion = %q, %v; want no candidates and no files", values, directive)
	}
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
	if err == nil || !strings.Contains(err.Error(), "unknown flag: --transport") {
		t.Fatalf("error = %v, want removed --transport rejection", err)
	}
}

func TestDNSCompletionFlagsFollowFinalResolver(t *testing.T) {
	t.Parallel()
	for _, resolvers := range [][]string{{"system", "dns"}, {"dns", "system"}} {
		values, _ := executeDNSCompletion(t, "dns", "--resolver", resolvers[0], "--resolver", resolvers[1], "--")
		joined := strings.Join(values, "\n")
		if strings.Contains(joined, "--port") != (resolvers[1] == "dns") {
			t.Errorf("flags after resolvers %q = %q; incorrect visibility for --port", resolvers, values)
		}
		if strings.Contains(joined, "--transport") {
			t.Errorf("flags after resolvers %q contain removed --transport: %q", resolvers, values)
		}
	}
}
