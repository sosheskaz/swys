package dns_test

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/sosheskaz/swys/internal/dnsquery"
)

func TestExampleDNSRecordTypeCompletion(t *testing.T) {
	t.Parallel()

	values, directive := executeDNSCompletion(t, "dns", "example.test", "A")
	assert.Equal(t, []string{"A", "AAAA"}, values)
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
}

func executeDNSCompletion(t *testing.T, args ...string) ([]string, cobra.ShellCompDirective) {
	t.Helper()
	root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
		System: stubSystemResolver{
			lookupNetIP: func(_ context.Context, _, _ string) ([]netip.Addr, error) {
				t.Fatal("completion performed a system lookup")
				return nil, nil
			},
			lookupAddr: func(_ context.Context, _ string) ([]string, error) {
				t.Fatal("completion performed a system lookup")
				return nil, nil
			},
		},
		PlaintextExchange: func(context.Context, *dns.Msg, dnsquery.Transport, string) (*dns.Msg, error) {
			t.Fatal("completion performed a direct DNS exchange")
			return nil, errUnexpectedSystemLookup
		},
		ConfiguredServers: func() ([]string, error) {
			t.Fatal("completion read configured DNS servers")
			return nil, errUnexpectedSystemLookup
		},
	})
	return executeDNSRootCompletion(t, root, args...)
}

func executeDNSRootCompletion(t *testing.T, root *cobra.Command, args ...string) ([]string, cobra.ShellCompDirective) {
	t.Helper()
	stdout, _, err := executeRootCommandStreams(t, root, append([]string{"__complete"}, args...)...)
	if err != nil {
		t.Fatalf("complete %q: %v", args, err)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[len(lines)-1], ":") {
		t.Fatalf("completion output = %q, want directive", stdout)
	}
	directive, err := strconv.Atoi(strings.TrimPrefix(lines[len(lines)-1], ":"))
	if err != nil {
		t.Fatalf("parse completion directive: %v", err)
	}
	values := lines[:len(lines)-1]
	for index := range values {
		values[index] = strings.SplitN(values[index], "\t", 2)[0]
	}
	return values, cobra.ShellCompDirective(directive)
}
