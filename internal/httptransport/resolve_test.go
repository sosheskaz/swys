package httptransport_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/internal/httptransport"
)

func TestParseHTTPResolves(t *testing.T) {
	t.Parallel()

	resolver, err := httptransport.ParseResolves([]string{
		"mixed.test:8443:192.0.2.1,[2001:db8::1]",
		"Example.TEST:443:192.0.2.1",
		"example.test:443:192.0.2.2",
		"[2001:db8::10]:8443:[2001:db8::20]",
	})
	require.NoError(t, err)

	addresses, port, exists := resolver.Lookup("EXAMPLE.test:443")
	if !exists || port != 443 || !slices.Equal(addresses, []netip.Addr{netip.MustParseAddr("192.0.2.2")}) {
		t.Fatalf("hostname lookup = %v, %d, %t", addresses, port, exists)
	}
	addresses, port, exists = resolver.Lookup("mixed.test:8443")
	wantMixed := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	}
	if !exists || port != 8443 || !slices.Equal(addresses, wantMixed) {
		t.Fatalf("mixed-address lookup = %v, %d, %t", addresses, port, exists)
	}
	addresses, port, exists = resolver.Lookup("[2001:db8::10]:8443")
	if !exists || port != 8443 || !slices.Equal(addresses, []netip.Addr{netip.MustParseAddr("2001:db8::20")}) {
		t.Fatalf("IPv6 lookup = %v, %d, %t", addresses, port, exists)
	}
}

func TestParseHTTPResolvesRejectsInvalidRules(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"",
		"example.test",
		"example.test:443",
		":443:192.0.2.1",
		"*:443:192.0.2.1",
		"+example.test:443:192.0.2.1",
		"-example.test:443",
		"example.test:0:192.0.2.1",
		"example.test:65536:192.0.2.1",
		"example.test:https:192.0.2.1",
		"example.test:443:backend.test",
		"example.test:443:2001:db8::1",
		"example.test:443:[192.0.2.1]",
		"example.test:443:192.0.2.1,",
		"[not-an-ip]:443:192.0.2.1",
		"tést.example:443:192.0.2.1",
	} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			resolver, err := httptransport.ParseResolves([]string{value})
			require.ErrorIs(t, err, httptransport.ErrInvalidResolve)
			require.Nil(t, resolver)
		})
	}
}
