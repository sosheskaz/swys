package dns_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/sosheskaz-systems/npc/internal/dnsquery"
)

var errUnexpectedSystemLookup = errors.New("unexpected system resolver call")

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
	if err != nil {
		t.Fatalf("npc dns example.test: %v", err)
	}
	want := ";; resolver: system\n;; server: unavailable\n" +
		";; status: unavailable; DNS packet metadata and TTLs unavailable\n\n" +
		"example.test.\t-\tIN\tA\t192.0.2.10\n"
	if stdout != want {
		t.Fatalf("stdout = %q", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want no diagnostics", stderr)
	}
}

func TestExampleDNSShortJSON(t *testing.T) {
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
	stdout, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "AAAA", "--short", "--format", "json")
	if err != nil {
		t.Fatalf("npc dns example.test AAAA --short --format json: %v", err)
	}
	if stdout != "[\n  \"2001:db8::10\",\n  \"2001:db8::20\"\n]\n" {
		t.Fatalf("stdout = %q", stdout)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n" +
		"  \"resolver\": \"system\",\n" +
		"  \"server\": null,\n" +
		"  \"transport\": null,\n" +
		"  \"query_name\": \"example.test.\",\n" +
		"  \"query_type\": \"A\",\n" +
		"  \"status\": null,\n" +
		"  \"id\": null,\n" +
		"  \"authoritative\": null,\n" +
		"  \"truncated\": null,\n" +
		"  \"recursion_available\": null,\n" +
		"  \"answers\": [\n" +
		"    {\n" +
		"      \"name\": \"example.test.\",\n" +
		"      \"type\": \"A\",\n" +
		"      \"class\": \"IN\",\n" +
		"      \"ttl\": null,\n" +
		"      \"value\": \"192.0.2.10\"\n" +
		"    }\n" +
		"  ]\n" +
		"}\n"
	if stdout != want {
		t.Fatalf("stdout = %q\nwant = %q", stdout, want)
	}
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
