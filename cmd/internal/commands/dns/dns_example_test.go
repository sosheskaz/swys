package dns_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/internal/dnsquery"
)

var errUnexpectedSystemLookup = errors.New("unexpected system resolver call")

func TestExampleDNSComparesResolversAnywhereInArguments(t *testing.T) {
	t.Parallel()
	firstHost, firstPort, firstConn, firstDone := startUDPFixture(t, func(request *dns.Msg) *dns.Msg {
		response := replyFor(request)
		response.Answer = []dns.RR{&dns.A{
			Hdr: dns.Header{Name: "example.test.", Class: dns.ClassINET, TTL: 60},
			A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.10")},
		}}
		return response
	})
	t.Cleanup(func() {
		assert.NoError(t, firstConn.Close())
		<-firstDone
	})
	first := net.JoinHostPort(firstHost, firstPort)
	secondHost, secondPort, secondConn, secondDone := startUDPFixture(t, func(request *dns.Msg) *dns.Msg {
		response := replyFor(request)
		response.Answer = []dns.RR{&dns.A{
			Hdr: dns.Header{Name: "example.test.", Class: dns.ClassINET, TTL: 60},
			A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.20")},
		}}
		return response
	})
	t.Cleanup(func() {
		assert.NoError(t, secondConn.Close())
		<-secondDone
	})
	second := net.JoinHostPort(secondHost, secondPort)
	stdout, stderr, err := executeRootStreams(t,
		"dns", "example.test", "@"+first, "A", "@"+second, "--format", "plain")
	require.NoError(t, err)
	assert.NoError(t, <-firstDone)
	assert.NoError(t, <-secondDone)
	assert.Empty(t, stderr)
	assert.Contains(t, stdout, first+" · udp")
	assert.Contains(t, stdout, second+" · udp")
	assert.Contains(t, stdout, "192.0.2.10")
	assert.Contains(t, stdout, "192.0.2.20")
	assert.Less(t, strings.Index(stdout, first), strings.Index(stdout, second))
}

func TestExampleDNSOutputSelectionAndEncoding(t *testing.T) {
	t.Parallel()
	newRoot := func() *cobra.Command {
		return newRootCmdWithDNSDependencies(dnsquery.Dependencies{
			System: stubSystemResolver{
				lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
					return []netip.Addr{
						netip.MustParseAddr("192.0.2.10"),
						netip.MustParseAddr("192.0.2.20"),
					}, nil
				},
			},
		})
	}

	defaultOutput, _, err := executeRootCommandStreams(t, newRoot(), "dns", "example.test")
	require.NoError(t, err)
	selectedResult, _, err := executeRootCommandStreams(t, newRoot(), "dns", "example.test", "--select", "result", "--format", "text")
	require.NoError(t, err)
	assert.Equal(t, defaultOutput, selectedResult, "explicit result selection")

	values, stderr, err := executeRootCommandStreams(t, newRoot(), "dns", "example.test", "--select", "values")
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.10\n192.0.2.20\n", values)
	assert.Empty(t, stderr)

	jsonValues, _, err := executeRootCommandStreams(t, newRoot(), "dns", "example.test", "--select", "values", "--format", "json")
	require.NoError(t, err)
	if want := "{\n  \"values\": [\n    \"192.0.2.10\",\n    \"192.0.2.20\"\n  ]\n}\n"; jsonValues != want {
		t.Errorf("selected JSON values = %q, want %q", jsonValues, want)
	}

	encoded, stderr, err := executeRootCommandStreams(t, newRoot(), "dns", "example.test", "--select", "values", "-e", "base64")
	require.NoError(t, err)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte(values)), encoded, "encode complete text including final newline")
	assert.Empty(t, stderr)

	encodedJSON, _, err := executeRootCommandStreams(t, newRoot(), "dns", "example.test", "--select", "values", "--format", "json", "--encoding", "base64")
	require.NoError(t, err)
	if want := base64.StdEncoding.EncodeToString([]byte(jsonValues)); encodedJSON != want {
		t.Errorf("encoded complete JSON = %q, want %q", encodedJSON, want)
	}
}

func TestExampleDNSUsesSystemResolverByDefault(t *testing.T) {
	t.Parallel()

	root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
		System: stubSystemResolver{
			lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
			},
		},
	})
	stdout, stderr, err := executeRootCommandStreams(t, root, "dns", "example.test")
	require.NoError(t, err, "swys dns example.test")
	want := "DNS · example.test. · A\n\n" +
		"    Resolver  system\n" +
		"    Server    unavailable\n" +
		"    Status    unavailable; DNS packet metadata and TTLs unavailable\n\n" +
		"  Answers\n" +
		"    Name           TTL  Class  Type  Value\n" +
		"    example.test.  -    IN     A     192.0.2.10\n"
	assert.Equal(t, want, stdout)
	assert.Empty(t, stderr, "diagnostics")
}

func TestExampleDNSValuesJSON(t *testing.T) {
	t.Parallel()

	root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
		System: stubSystemResolver{
			lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{
					netip.MustParseAddr("2001:db8::10"),
					netip.MustParseAddr("2001:db8::20"),
				}, nil
			},
		},
	})
	stdout, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "AAAA", "--select", "values", "--format", "json")
	require.NoError(t, err, "swys dns example.test AAAA --select values --format json")
	assert.JSONEq(t, `{"values": ["2001:db8::10", "2001:db8::20"]}`, stdout)
}

func TestDNSJSONSchemaIsByteStableAcrossCoreBoundary(t *testing.T) {
	t.Parallel()

	root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
		System: stubSystemResolver{
			lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
			},
		},
	})
	stdout, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "--format", "json")
	require.NoError(t, err)
	want := `{
  "results": [
    {
      "resolver": "system",
      "server": null,
      "transport": null,
      "query_name": "example.test.",
      "query_type": "A",
      "status": null,
      "id": null,
      "authoritative": null,
      "truncated": null,
      "recursion_available": null,
      "answers": [
        {
          "name": "example.test.",
          "type": "A",
          "class": "IN",
          "ttl": null,
          "value": "192.0.2.10"
        }
      ]
    }
  ]
}
`
	assert.Equal(t, want, stdout)
}

type stubSystemResolver struct {
	lookupNetIP func(context.Context, string, string) ([]netip.Addr, error)
	lookupAddr  func(context.Context, string) ([]string, error)
}

func (resolver stubSystemResolver) LookupNetIP(ctx context.Context, network, name string) ([]netip.Addr, error) {
	if resolver.lookupNetIP == nil {
		return nil, fmt.Errorf("%w: LookupNetIP", errUnexpectedSystemLookup)
	}
	return resolver.lookupNetIP(ctx, network, name)
}

func (resolver stubSystemResolver) LookupAddr(ctx context.Context, address string) ([]string, error) {
	if resolver.lookupAddr == nil {
		return nil, fmt.Errorf("%w: LookupAddr", errUnexpectedSystemLookup)
	}
	return resolver.lookupAddr(ctx, address)
}
