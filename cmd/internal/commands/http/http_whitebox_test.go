package http

import (
	"crypto/tls"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
)

func TestHTTPDefaultURLScheme(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ input, want string }{
		{"example.com", "https://example.com"},
		{"localhost:8443/path?q=one", "https://localhost:8443/path?q=one"},
		{"[::1]:8443/path", "https://[::1]:8443/path"},
		{"//example.com/path", "https://example.com/path"},
		{"example.com/?next=http://other.test", "https://example.com/?next=http://other.test"},
		{"http://example.com", "http://example.com"},
		{"https://example.com", "https://example.com"},
	} {
		t.Run(test.input, func(t *testing.T) {
			t.Parallel()
			command := newHTTPCmd()
			command.Flags().AddFlagSet(command.PersistentFlags())
			_, address, err := httpMethodURL(command, []string{test.input})
			if err != nil {
				t.Fatal(err)
			}
			if address.String() != test.want {
				t.Fatalf("URL = %q, want %q", address, test.want)
			}
		})
	}
	for _, input := range []string{"", "/path", "http://", "ftp://example.com", "localhost:bad", "http:/example.com", "https:/example.com"} {
		t.Run("invalid/"+input, func(t *testing.T) {
			t.Parallel()
			command := newHTTPCmd()
			command.Flags().AddFlagSet(command.PersistentFlags())
			if _, _, err := httpMethodURL(command, []string{input}); err == nil {
				t.Fatalf("invalid URL %q accepted", input)
			}
		})
	}
}

func TestParseHTTPResolves(t *testing.T) {
	t.Parallel()

	resolver, err := parseHTTPResolves([]string{
		"mixed.test:8443:192.0.2.1,[2001:db8::1]",
		"Example.TEST:443:192.0.2.1",
		"example.test:443:192.0.2.2",
		"[2001:db8::10]:8443:[2001:db8::20]",
	})
	require.NoError(t, err)

	addresses, port, exists := resolver.lookup("EXAMPLE.test:443")
	if !exists || port != 443 || !slices.Equal(addresses, []netip.Addr{netip.MustParseAddr("192.0.2.2")}) {
		t.Fatalf("hostname lookup = %v, %d, %t", addresses, port, exists)
	}
	addresses, port, exists = resolver.lookup("mixed.test:8443")
	wantMixed := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	}
	if !exists || port != 8443 || !slices.Equal(addresses, wantMixed) {
		t.Fatalf("mixed-address lookup = %v, %d, %t", addresses, port, exists)
	}
	addresses, port, exists = resolver.lookup("[2001:db8::10]:8443")
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
			resolver, err := parseHTTPResolves([]string{value})
			if !errors.Is(err, ErrInvalidFlags) {
				t.Fatalf("error = %v, want invalid HTTP options", err)
			}
			if resolver != nil {
				t.Fatalf("resolver = %#v, want nil", resolver)
			}
		})
	}
}

func newHTTPCmd() *cobra.Command { return NewCommand(commandio.NewLifecycle()) }

func newTLSCertificateChain(t *testing.T) tls.Certificate {
	t.Helper()
	return testcmd.NewTLSCertificateChain(t)
}
