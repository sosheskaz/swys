package dns_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/internal/dnsquery"
)

func TestExampleDNSPlainReport(t *testing.T) {
	t.Parallel()
	root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{System: stubSystemResolver{
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
		},
	}})
	output, stderr, err := executeRootCommandStreams(t, root, "dns", "example.test", "--format", "plain")
	require.NoError(t, err)
	assert.Empty(t, stderr)
	assert.Contains(t, output, "DNS · example.test. · A\n")
	assert.Contains(t, output, "Resolver")
	assert.Contains(t, output, "unavailable")
	assert.Contains(t, output, "192.0.2.10")
	assert.NotContains(t, output, "\x1b")
}
