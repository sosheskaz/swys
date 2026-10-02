package dns_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/internal/dnsquery"
)

var errUnexpectedSystemLookup = errors.New("unexpected system resolver call")

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
	if want := "[\n  \"192.0.2.10\",\n  \"192.0.2.20\"\n]\n"; jsonValues != want {
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
	require.NoError(t, err, "npc dns example.test")
	want := ";; resolver: system\n;; server: unavailable\n" +
		";; status: unavailable; DNS packet metadata and TTLs unavailable\n\n" +
		"example.test.\t-\tIN\tA\t192.0.2.10\n"
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
	require.NoError(t, err, "npc dns example.test AAAA --select values --format json")
	assert.Equal(t, "[\n  \"2001:db8::10\",\n  \"2001:db8::20\"\n]\n", stdout)
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
