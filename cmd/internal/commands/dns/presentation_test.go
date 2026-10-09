package dns_test

import (
	"context"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/cli/presentation"
	"github.com/sosheskaz/swys/internal/dnsquery"
)

func TestDNSReportedColumns(t *testing.T) {
	t.Parallel()
	for _, width := range []int{0, 20, 40, 60, 80, 99, 100, 101, 120, 160, 240} {
		t.Run(strconv.Itoa(width), func(t *testing.T) {
			t.Parallel()
			root := presentationDNSRoot()
			root.SetContext(presentation.WithDependencies(t.Context(), presentation.Dependencies{
				Terminal: func(io.Writer) (bool, int) { return true, width },
				Getenv:   func(string) (string, bool) { return "", false },
			}))
			output, stderr, err := executeRootCommandStreams(t, root, "dns", "@192.0.2.53", "example.test", "ANY")
			require.NoError(t, err)
			assert.Empty(t, stderr)
			assert.Contains(t, output, "\x1b[", "terminal styles")
			visible := regexp.MustCompile(`\x1b\[[0-9;]*m`).ReplaceAllString(output, "")
			for _, value := range []string{"192.0.2.10", "2001:db8::10", "界界.example.test.", strings.Repeat("A", 184)} {
				assert.Contains(t, visible, value, "width=%d", width)
			}
			assert.Equal(t, width < 240, strings.Contains(visible, "TTL / Class"), "available columns determine table layout")
			t.Logf("reported columns=%d\n%s", width, visible)
		})
	}
}

func presentationDNSRoot() *cobra.Command {
	return newRootCmdWithDNSDependencies(dnsquery.Dependencies{
		PlaintextExchange: func(_ context.Context, request *dns.Msg, _ dnsquery.Transport, _ string) (*dns.Msg, error) {
			response := replyFor(request)
			response.Answer = []dns.RR{
				&dns.A{Hdr: dns.Header{Name: "example.test.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.10")}},
				&dns.AAAA{Hdr: dns.Header{Name: "ipv6.example.test.", Class: dns.ClassINET, TTL: 300}, AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2001:db8::10")}},
				&dns.TXT{Hdr: dns.Header{Name: "界界.example.test.", Class: dns.ClassINET, TTL: 60}, TXT: rdata.TXT{Txt: []string{"café e\u0301 wide 界界"}}},
				&dns.TXT{Hdr: dns.Header{Name: "long.example.test.", Class: dns.ClassINET, TTL: 60}, TXT: rdata.TXT{Txt: []string{strings.Repeat("A", 184)}}},
				&dns.TXT{Hdr: dns.Header{Name: "policy.example.test.", Class: dns.ClassINET, TTL: 3600}, TXT: rdata.TXT{Txt: []string{
					"v=spf1 include:mail.example.test include:backup.example.test -all",
				}}},
			}
			return response, nil
		},
	})
}

func TestDNSInvalidStyleBeforeQueryAndOutput(t *testing.T) {
	t.Parallel()
	root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{System: stubSystemResolver{
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			t.Error("invalid presentation reached the resolver")
			return nil, errTestDNSLookupFailed
		},
	}})
	path := filepath.Join(t.TempDir(), "report")
	require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
	output, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "--style", "bad", "-o", path)
	require.ErrorIs(t, err, presentation.ErrStyle)
	assert.Empty(t, output)
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "preserve", string(contents))
}
