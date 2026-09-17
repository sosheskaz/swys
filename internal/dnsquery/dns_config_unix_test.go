//go:build !windows

package dnsquery

import (
	"slices"
	"strings"
	"testing"
)

func TestParseConfiguredDNSServers(t *testing.T) {
	t.Parallel()

	servers, err := parseConfiguredDNSServers(strings.NewReader(
		"search example.test\n# comment\nnameserver 192.0.2.53\nnameserver 2001:db8::53 # local\n",
	))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(servers, []string{"192.0.2.53", "2001:db8::53"}) {
		t.Fatalf("servers = %q", servers)
	}
}
