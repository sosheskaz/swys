package dns_test

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	byteencoding "github.com/sosheskaz/swys/cmd/internal/cli/encoding"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
	"github.com/sosheskaz/swys/internal/dnsquery"
)

var (
	errUnexpectedConfiguredServerLookup = errors.New("unexpected configured server lookup")
	errTestDNSExchangeFailed            = errors.New("test DNS exchange failed")
	errTestDNSLookupFailed              = errors.New("test DNS lookup failed")
)

func TestDNSAliasesUseTheSameSyntax(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"dig", "nslookup"}, newDNSCmd(defaultDNSDependencies()).Aliases)
	for _, alias := range []string{"dns", "dig", "nslookup"} {
		t.Run(alias, func(t *testing.T) {
			t.Parallel()
			root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
				System: stubSystemResolver{
					lookupNetIP: func(_ context.Context, network, name string) ([]netip.Addr, error) {
						if network != "ip4" || name != "example.test" {
							t.Fatalf("lookup = %s %q", network, name)
						}
						return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
					},
				},
			})
			stdout, _, err := executeRootCommandStreams(t, root, alias, "example.test", "A", "--select", "values")
			require.NoError(t, err)
			assert.Equal(t, "192.0.2.1\n", stdout)
		})
	}
}

func TestDNSResolverPositions(t *testing.T) {
	t.Parallel()
	for _, command := range []string{"dns", "dig", "nslookup"} {
		for _, args := range [][]string{
			{"@192.0.2.53", "example.test", "A"},
			{"example.test", "@192.0.2.53", "A"},
			{"example.test", "A", "@192.0.2.53"},
			{"example.test", "@192.0.2.53"},
		} {
			t.Run(command+"/"+strings.Join(args, "_"), func(t *testing.T) {
				t.Parallel()
				root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
					PlaintextExchange: func(_ context.Context, request *dns.Msg, transport dnsquery.Transport, address string) (*dns.Msg, error) {
						require.Len(t, request.Question, 1)
						assert.Equal(t, "192.0.2.53:53", address)
						assert.Equal(t, dnsquery.TransportUDP, transport)
						assert.Equal(t, "example.test.", request.Question[0].Header().Name)
						assert.Equal(t, dns.TypeA, dns.RRToType(request.Question[0]))
						return standardDNSReply(request), nil
					},
				})
				invocation := append([]string{command}, args...)
				invocation = append(invocation, "--select", "values")
				stdout, stderr, err := executeRootCommandStreams(t, root, invocation...)
				require.NoError(t, err)
				assert.Equal(t, "192.0.2.44\n", stdout)
				assert.Empty(t, stderr)
			})
		}
	}
}

func TestDNSMultipleResolverOutput(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		flags []string
	}{
		{name: "result JSON", flags: []string{"--format", "json"}},
		{name: "values text", flags: []string{"--select", "values"}},
		{name: "values JSON encoded", flags: []string{"--select", "values", "--format", "json", "--encoding", "base64"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var addresses []string
			root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
				PlaintextExchange: func(_ context.Context, request *dns.Msg, _ dnsquery.Transport, address string) (*dns.Msg, error) {
					addresses = append(addresses, address)
					response := standardDNSReply(request)
					if address == "192.0.2.54:53" {
						response.Rcode = dns.RcodeNameError
						response.Answer = nil
					}
					return response, nil
				},
			})
			args := []string{"dns", "@192.0.2.53", "example.test", "@tcp://192.0.2.54", "A", "@192.0.2.53"}
			stdout, stderr, err := executeRootCommandStreams(t, root, append(args, test.flags...)...)
			require.NoError(t, err)
			assert.Empty(t, stderr)
			assert.Equal(t, []string{"192.0.2.53:53", "192.0.2.54:53", "192.0.2.53:53"}, addresses)
			switch test.name {
			case "result JSON":
				var results []dnsquery.Result
				require.NoError(t, json.Unmarshal([]byte(stdout), &results))
				require.Len(t, results, 3)
				for i, wantServer := range addresses {
					require.NotNil(t, results[i].Server)
					assert.Equal(t, wantServer, *results[i].Server)
				}
				require.NotNil(t, results[1].Transport)
				require.NotNil(t, results[1].Status)
				assert.Equal(t, dnsquery.TransportTCP, *results[1].Transport)
				assert.Equal(t, "NXDOMAIN", *results[1].Status)
				assert.Empty(t, results[1].Answers)
			case "values text":
				assert.Equal(t, "192.0.2.44\n192.0.2.44\n", stdout)
			case "values JSON encoded":
				decoded, decodeErr := base64.StdEncoding.DecodeString(stdout)
				require.NoError(t, decodeErr)
				assert.JSONEq(t, `["192.0.2.44", "192.0.2.44"]`, string(decoded))
			}
		})
	}
}

func TestDNSMultipleResolverFailures(t *testing.T) {
	t.Parallel()
	for _, fail := range []string{"192.0.2.53:53", "192.0.2.54:53", "all"} {
		t.Run(fail, func(t *testing.T) {
			t.Parallel()
			path := writeExistingDNSOutput(t)
			var addresses []string
			root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
				PlaintextExchange: func(_ context.Context, request *dns.Msg, _ dnsquery.Transport, address string) (*dns.Msg, error) {
					addresses = append(addresses, address)
					if fail == "all" || address == fail {
						return nil, errTestDNSExchangeFailed
					}
					return standardDNSReply(request), nil
				},
			})
			original := t.Context()
			root.SetContext(original)
			stdout, _, err := executeRootCommandStreams(t, root,
				"dns", "@192.0.2.53", "example.test", "A", "@192.0.2.54", "--format", "json", "--output", path)
			require.ErrorIs(t, err, errTestDNSExchangeFailed)
			assert.Empty(t, stdout)
			assert.Equal(t, []string{"192.0.2.53:53", "192.0.2.54:53"}, addresses)
			command, _, findErr := root.Find([]string{"dns"})
			require.NoError(t, findErr)
			assert.Equal(t, original, command.Context(), "context restored after lookup failure")
			if fail == "all" {
				assertExistingDNSOutput(t, path)
				require.ErrorContains(t, err, "192.0.2.53:53")
				require.ErrorContains(t, err, "192.0.2.54:53")
				return
			}
			require.ErrorContains(t, err, fail)
			data, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			var results []dnsquery.Result
			require.NoError(t, json.Unmarshal(data, &results))
			require.Len(t, results, 1, "partial success retains the multi-resolver JSON array")
			require.NotNil(t, results[0].Server)
			assert.NotEqual(t, fail, *results[0].Server)
			require.Len(t, results[0].Answers, 1)
			assert.Equal(t, "192.0.2.44", results[0].Answers[0].Value)
		})
	}
}

func TestDNSPartialFailurePreservesOutputErrors(t *testing.T) {
	t.Parallel()
	for _, destination := range []string{"writer", "directory"} {
		t.Run(destination, func(t *testing.T) {
			t.Parallel()
			root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
				PlaintextExchange: func(_ context.Context, request *dns.Msg, _ dnsquery.Transport, address string) (*dns.Msg, error) {
					if address == "192.0.2.53:53" {
						return nil, errTestDNSExchangeFailed
					}
					return standardDNSReply(request), nil
				},
			})
			args := []string{"dns", "example.test", "@192.0.2.53", "@192.0.2.54", "--select", "values"}
			output := io.Discard
			if destination == "writer" {
				reader, writer := io.Pipe()
				require.NoError(t, reader.Close())
				t.Cleanup(func() { assert.NoError(t, writer.Close()) })
				output = writer
			} else {
				args = append(args, "--output", t.TempDir())
			}
			err := testcmd.Run(t, root, nil, output, io.Discard, args...)
			require.ErrorIs(t, err, errTestDNSExchangeFailed)
			if destination == "writer" {
				require.ErrorIs(t, err, io.ErrClosedPipe)
			} else {
				require.ErrorIs(t, err, commandio.ErrOutputIsDirectory)
			}
		})
	}
}

func TestDNSValidatesAllResolversBeforeQueries(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"@192.0.2.53", "example.test", "A", "@"},
		{"@192.0.2.53", "example.test", "@dot://192.0.2.54"},
		{"example.test", "A", "@192.0.2.53", "extra"},
		{"@192.0.2.53", "@192.0.2.54"},
		{"example.test", "@192.0.2.53", "--resolver", "system"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			t.Parallel()
			var queries int
			root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
				PlaintextExchange: func(context.Context, *dns.Msg, dnsquery.Transport, string) (*dns.Msg, error) {
					queries++
					return nil, errTestDNSExchangeFailed
				},
			})
			path := writeExistingDNSOutput(t)
			invocation := append([]string{"dns"}, args...)
			invocation = append(invocation, "--output", path)
			_, _, err := executeRootCommandStreams(t, root, invocation...)
			require.ErrorIs(t, err, errInvalidDNSOptions)
			assert.Zero(t, queries)
			assertExistingDNSOutput(t, path)
		})
	}
}

func TestDNSRejectsInvalidOptionsBeforeOpeningOutput(t *testing.T) {
	t.Parallel()
	tests := [][]string{
		{"example.test", "MX"},
		{"@127.0.0.1", "example.test", "--resolver", "system"},
		{"@dot://127.0.0.1", "example.test"},
		{"example.test", "--transport", "dot"},
		{"example.test", "--resolver", "native"},
		{"example.test", "--format", "yaml"},
		{"example.test", "--port", "0"},
		{"example.test", "--timeout", "-1s"},
		{"not-an-ip", "--reverse"},
		{"example.test", "MX", "--reverse"},
		{"example.test", "AXFR", "--resolver", "dns"},
		{"example.test", "IXFR", "--resolver", "dns"},
		{"@", "example.test"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "output")
			require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
			args = append(args, "--output", path)
			_, _, err := executeRootStreams(t, args...)
			require.Error(t, err)
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, "preserve", string(data), "output file")
		})
	}
}

func TestDNSRejectsExplicitInputBeforeQuery(t *testing.T) {
	t.Parallel()
	var queries atomic.Int64
	root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
		System: stubSystemResolver{lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			queries.Add(1)
			return nil, errTestDNSLookupFailed
		}},
	})
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input")
	outputPath := filepath.Join(dir, "output")
	require.NoError(t, os.WriteFile(inputPath, []byte("unused input"), 0o600))
	require.NoError(t, os.WriteFile(outputPath, []byte("preserve"), 0o600))
	stdout, stderr, err := executeRootCommandStreams(t, root,
		"dns", "example.test", "--input", inputPath, "--output", outputPath,
	)
	assert.Zero(t, queries.Load(), "irrelevant input reached DNS preparation")
	contents, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	assert.Equal(t, "preserve", string(contents))
	assert.Empty(t, stdout)
	assert.Empty(t, stderr)
	require.ErrorContains(t, err, "--input")
}

func TestDNSInvalidEncodingRejectsBeforeQuery(t *testing.T) {
	t.Parallel()
	var queries atomic.Int64
	host, port, connection, done := startUDPFixture(t, func(request *dns.Msg) *dns.Msg {
		queries.Add(1)
		return standardDNSReply(request)
	})
	t.Cleanup(func() {
		_ = connection.Close() //nolint:errcheck // release a fixture that received no query
		<-done
	})
	path := filepath.Join(t.TempDir(), "output")
	require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
	_, _, err := executeRootStreams(t, "dns", "@udp://"+net.JoinHostPort(host, port), "example.test", "--encoding", "rot13", "--output", path)
	require.ErrorIs(t, err, byteencoding.ErrUnknownOutputEncoding)
	assert.Zero(t, queries.Load(), "invalid encoding reached the DNS server")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "preserve", string(data))
}

func TestDNSRejectsRemovedShortFlag(t *testing.T) {
	t.Parallel()
	root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
		System: stubSystemResolver{lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
		}},
	})
	_, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "--short")
	require.ErrorContains(t, err, "unknown flag: --short")
}

func TestDNSInvalidPresentationPreservesOutput(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		want error
		name string
		args []string
	}{
		{name: "selection", args: []string{"--select", "missing"}, want: errInvalidDNSOptions},
		{name: "encoding", args: []string{"--encoding", "rot13"}, want: byteencoding.ErrUnknownOutputEncoding},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "output")
			require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
			root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
				System: stubSystemResolver{lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
				}},
			})
			args := append([]string{"dns", "example.test", "--output", path}, test.args...)
			_, _, executeErr := executeRootCommandStreams(t, root, args...)
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, "preserve", string(data), "destination after invalid %s", test.name)
			require.ErrorIs(t, executeErr, test.want)
		})
	}
}

func TestDNSSystemPTRAndMetadata(t *testing.T) {
	t.Parallel()
	root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{System: stubSystemResolver{lookupAddr: func(_ context.Context, address string) ([]string, error) {
		if address != "192.0.2.8" {
			t.Fatalf("address = %q", address)
		}
		return []string{"ptr.example.test."}, nil
	}}})
	stdout, _, err := executeRootCommandStreams(t, root, "dns", "192.0.2.8", "-x", "--format", "json")
	require.NoError(t, err)
	var result dnsquery.Result
	require.NoError(t, json.Unmarshal([]byte(stdout), &result))
	if result.Server != nil || result.Status != nil || result.Answers[0].TTL != nil || result.Answers[0].Value != "ptr.example.test." {
		t.Fatalf("result = %+v", result)
	}
}

func TestDNSSystemResolverIsInjectedPerCommand(t *testing.T) {
	t.Parallel()
	for _, address := range []string{"192.0.2.11", "192.0.2.12"} {
		t.Run(address, func(t *testing.T) {
			t.Parallel()
			root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
				System: stubSystemResolver{lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr(address)}, nil
				}},
			})
			stdout, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "--select", "values")
			require.NoError(t, err)
			assert.Equal(t, address+"\n", stdout)
		})
	}
}

func TestDNSDirectRetriesTruncatedUDPOverTCP(t *testing.T) {
	t.Parallel()
	var transports []dnsquery.Transport
	deps := dnsquery.Dependencies{
		PlaintextExchange: func(_ context.Context, request *dns.Msg, transport dnsquery.Transport, address string) (*dns.Msg, error) {
			transports = append(transports, transport)
			if address != "127.0.0.1:5353" {
				t.Fatalf("address = %q", address)
			}
			response := replyFor(request)
			if transport == dnsquery.TransportUDP {
				response.Truncated = true
				return response, nil
			}
			response.Answer = []dns.RR{&dns.A{
				Hdr: dns.Header{Name: "example.test.", Class: dns.ClassINET, TTL: 60},
				A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.20")},
			}}
			return response, nil
		},
		ConfiguredServers: func() ([]string, error) { return nil, errUnexpectedConfiguredServerLookup },
	}
	root := newRootCmdWithDNSDependencies(deps)
	stdout, _, err := executeRootCommandStreams(t, root, "dns", "@127.0.0.1", "example.test", "--port", "5353", "--format", "json")
	require.NoError(t, err)
	wantTransports := []dnsquery.Transport{dnsquery.TransportUDP, dnsquery.TransportTCP}
	assert.Equal(t, wantTransports, transports)
	assert.Contains(t, stdout, `"transport": "tcp"`)
	assert.Contains(t, stdout, `"ttl": 60`)
}

func TestDNSDirectLocalUDPTruncationFallback(t *testing.T) {
	t.Parallel()
	listenConfig := net.ListenConfig{}
	tcpListener, err := listenConfig.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	udpConn, err := listenConfig.ListenPacket(t.Context(), "udp4", tcpListener.Addr().String())
	if err != nil {
		if closeErr := tcpListener.Close(); closeErr != nil {
			t.Errorf("close TCP listener: %v", closeErr)
		}
		t.Fatal(err)
	}
	udpDone := serveUDPFixtureOnce(udpConn, func(request *dns.Msg) *dns.Msg {
		response := replyFor(request)
		response.Truncated = true
		return response
	})
	tcpDone := serveTCPAnswerFixture(tcpListener)

	host, port, err := net.SplitHostPort(tcpListener.Addr().String())
	require.NoError(t, err)
	root := newRootCmd()
	stdout, _, err := executeRootCommandStreams(t, root, "dns", "@"+host, "fixture.example", "--port", port, "--format", "json")
	require.NoError(t, err)
	require.Contains(t, stdout, `"transport": "tcp"`)
	require.Contains(t, stdout, `"value": "192.0.2.45"`)
	require.NoError(t, <-udpDone)
	require.NoError(t, <-tcpDone)
	require.NoError(t, errors.Join(udpConn.Close(), tcpListener.Close()), "close DNS fixtures")
}

func TestDNSDirectLocalWireRendersEmptyRDATA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		check func(*testing.T, string)
		name  string
		args  []string
	}{
		{
			name: "text",
			check: func(t *testing.T, output string) {
				t.Helper()
				for _, recordType := range []string{"OPT", "NXNAME", "IXFR", "AXFR", "ANY"} {
					assert.Contains(t, output, "  "+recordType+strings.Repeat(" ", 8-len(recordType))+"\n", "empty %s value", recordType)
				}
			},
		},
		{
			name: "json",
			args: []string{"--format", "json"},
			check: func(t *testing.T, output string) {
				t.Helper()
				var result dnsquery.Result
				require.NoError(t, json.Unmarshal([]byte(output), &result), "decode JSON output")
				assertEmptyDNSAnswerValues(t, result.Answers)
			},
		},
		{
			name: "values",
			args: []string{"--select", "values"},
			check: func(t *testing.T, output string) {
				t.Helper()
				assert.Equal(t, strings.Repeat("\n", 5), output, "five empty values")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			host, port, connection, done := startUDPFixture(t, func(request *dns.Msg) *dns.Msg {
				response := replyFor(request)
				response.Answer = emptyRDATAAnswers()
				return response
			})
			root := newRootCmd()
			args := []string{"dns", "@" + host, "fixture.example", "ANY", "--port", port}
			args = append(args, test.args...)
			stdout, panicValue, err := executeRootCommandStreamsRecover(root, args...)
			finishUDPFixture(t, connection, done)
			if panicValue != nil {
				t.Fatalf("rendering empty RDATA panicked: %v", panicValue)
			}
			require.NoError(t, err)
			test.check(t, stdout)
		})
	}
}

func emptyRDATAAnswers() []dns.RR {
	header := dns.Header{Name: "fixture.example.", Class: dns.ClassINET, TTL: 30}
	return []dns.RR{
		&dns.OPT{Hdr: header},
		&dns.NXNAME{Hdr: header},
		&dns.IXFR{Hdr: header},
		&dns.AXFR{Hdr: header},
		&dns.ANY{Hdr: header},
	}
}

func assertEmptyDNSAnswerValues(t *testing.T, answers []dnsquery.Answer) {
	t.Helper()
	wantTypes := []string{"OPT", "NXNAME", "IXFR", "AXFR", "ANY"}
	require.Len(t, answers, len(wantTypes))
	for index, answer := range answers {
		assert.Equal(t, wantTypes[index], answer.Type, "answer %d type", index)
		assert.Empty(t, answer.Value, "answer %d value", index)
	}
}

func executeRootCommandStreamsRecover(root *cobra.Command, args ...string) (string, any, error) {
	var stdout string
	var panicValue any
	var executeErr error
	func() {
		defer func() {
			panicValue = recover()
		}()
		var stdoutBuffer strings.Builder
		var stderrBuffer strings.Builder
		root.SetOut(&stdoutBuffer)
		root.SetErr(&stderrBuffer)
		root.SetArgs(args)
		command, runErr := root.ExecuteC()
		stdout = stdoutBuffer.String()
		executeErr = errors.Join(runErr, closeCommandIO(command))
	}()
	return stdout, panicValue, executeErr
}

func TestDNSDirectServerPortNormalization(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		server      string
		portFlag    string
		wantAddress string
	}{
		{name: "default IPv4 port", server: "192.0.2.1", wantAddress: "192.0.2.1:53"},
		{name: "hostname", server: "resolver.example", wantAddress: "resolver.example:53"},
		{name: "balanced bracketed hostname", server: "[resolver.example]", wantAddress: "resolver.example:53"},
		{name: "balanced bracketed IPv4", server: "[192.0.2.1]", wantAddress: "192.0.2.1:53"},
		{name: "IPv6 zone", server: "[fe80::1%lo0]:5353", wantAddress: "[fe80::1%lo0]:5353"},
		{name: "minimum flag port", server: "192.0.2.1", portFlag: "1", wantAddress: "192.0.2.1:1"},
		{name: "maximum flag port", server: "192.0.2.1", portFlag: "65535", wantAddress: "192.0.2.1:65535"},
		{name: "inline port", server: "192.0.2.1:5353", wantAddress: "192.0.2.1:5353"},
		{name: "agreeing inline and flag port", server: "192.0.2.1:5353", portFlag: "5353", wantAddress: "192.0.2.1:5353"},
		{name: "normalized inline port", server: "192.0.2.1:0053", portFlag: "53", wantAddress: "192.0.2.1:53"},
		{name: "default IPv6 port", server: "2001:db8::53", wantAddress: "[2001:db8::53]:53"},
		{name: "bracketed IPv6 flag port", server: "[2001:db8::53]", portFlag: "5353", wantAddress: "[2001:db8::53]:5353"},
		{name: "IPv6 inline port", server: "[2001:db8::53]:5353", wantAddress: "[2001:db8::53]:5353"},
		{name: "agreeing IPv6 inline and flag port", server: "[2001:db8::53]:5353", portFlag: "5353", wantAddress: "[2001:db8::53]:5353"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var gotAddress string
			root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
				PlaintextExchange: func(_ context.Context, request *dns.Msg, _ dnsquery.Transport, address string) (*dns.Msg, error) {
					gotAddress = address
					return replyFor(request), nil
				},
				ConfiguredServers: func() ([]string, error) { return nil, errUnexpectedConfiguredServerLookup },
			})
			args := []string{"dns", "@" + test.server, "example.test"}
			if test.portFlag != "" {
				args = append(args, "--port", test.portFlag)
			}
			_, _, err := executeRootCommandStreams(t, root, args...)
			require.NoError(t, err)
			assert.Equal(t, test.wantAddress, gotAddress, "exchange address")
		})
	}
}

func TestDNSDirectRejectsServerPortConflictsBeforeExchangeOrOutput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		server   string
		portFlag string
	}{
		{name: "explicit default conflicts", server: "192.0.2.1:5353", portFlag: "53"},
		{name: "nondefault flag conflicts", server: "192.0.2.1:53", portFlag: "5353"},
		{name: "IPv6 explicit default conflicts", server: "[2001:db8::53]:5353", portFlag: "53"},
		{name: "zero inline port", server: "192.0.2.1:0"},
		{name: "oversized inline port", server: "192.0.2.1:65536"},
		{name: "nonnumeric inline port", server: "192.0.2.1:dns"},
		{name: "empty inline port", server: "192.0.2.1:"},
		{name: "empty host", server: ":53"},
		{name: "empty bracketed host", server: "[]:53"},
		{name: "extra IPv4 port", server: "192.0.2.1:53:54", portFlag: "53"},
		{name: "colon-rich hostname", server: "host:80:90:100"},
		{name: "invalid bracketed IPv6 inline port", server: "[a:b:c]:53"},
		{name: "unclosed IPv6 bracket", server: "[2001:db8::1"},
		{name: "unclosed malformed bracket", server: "[a:b:c"},
		{name: "unopened IPv6 bracket", server: "2001:db8::1]"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			outputPath := filepath.Join(t.TempDir(), "output")
			require.NoError(t, os.WriteFile(outputPath, []byte("preserve"), 0o600))
			exchanged := false
			root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
				PlaintextExchange: func(_ context.Context, request *dns.Msg, _ dnsquery.Transport, _ string) (*dns.Msg, error) {
					exchanged = true
					return replyFor(request), nil
				},
				ConfiguredServers: func() ([]string, error) { return nil, errUnexpectedConfiguredServerLookup },
			})
			args := []string{"dns", "@" + test.server, "example.test", "--output", outputPath}
			if test.portFlag != "" {
				args = append(args, "--port", test.portFlag)
			}
			_, _, err := executeRootCommandStreams(t, root, args...)
			require.ErrorIs(t, err, errInvalidDNSOptions)
			assert.False(t, exchanged, "invalid server port reached DNS exchange")
			contents, readErr := os.ReadFile(outputPath)
			require.NoError(t, readErr)
			assert.Equal(t, "preserve", string(contents), "output file")
		})
	}
}

func serveUDPFixtureOnce(connection net.PacketConn, reply func(*dns.Msg) *dns.Msg) <-chan error {
	done := make(chan error, 1)
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		length, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			done <- fmt.Errorf("read UDP DNS fixture request: %w", err)
			return
		}
		request := &dns.Msg{Data: append([]byte(nil), buffer[:length]...)}
		if err := request.Unpack(); err != nil {
			done <- fmt.Errorf("unpack UDP DNS fixture request: %w", err)
			return
		}
		response := reply(request)
		if err := response.Pack(); err != nil {
			done <- fmt.Errorf("pack UDP DNS fixture response: %w", err)
			return
		}
		if _, err := connection.WriteTo(response.Data, peer); err != nil {
			done <- fmt.Errorf("write UDP DNS fixture response: %w", err)
		}
	}()
	return done
}

func TestDNSDirectRejectsWrongOpcodeFromWire(t *testing.T) {
	t.Parallel()
	host, port, connection, done := startUDPFixture(t, func(request *dns.Msg) *dns.Msg {
		response := replyFor(request)
		response.Opcode = dns.OpcodeUpdate
		return response
	})
	root := newRootCmd()
	_, _, err := executeRootCommandStreams(t, root, "dns", "@"+host, "fixture.example", "--port", port)
	require.ErrorIs(t, err, errDNSResponseMismatch)
	finishUDPFixture(t, connection, done)
}

func TestDNSDirectEscapesWireNamesInText(t *testing.T) {
	t.Parallel()
	host, port, connection, done := startUDPFixture(t, func(request *dns.Msg) *dns.Msg {
		response := replyFor(request)
		response.Answer = []dns.RR{&dns.CNAME{
			Hdr:   dns.Header{Name: "bad\x1b[32m.fixture.example.", Class: dns.ClassINET, TTL: 30},
			CNAME: rdata.CNAME{Target: "bad\x1b[31m.target.example."},
		}}
		return response
	})
	root := newRootCmd()
	stdout, _, err := executeRootCommandStreams(
		t,
		root,
		"dns", "@"+host, "fixture.example", "CNAME", "--port", port,
	)
	require.NoError(t, err)
	require.NotContains(t, stdout, "\x1b", "unsafe DNS names")
	require.Contains(t, stdout, `bad\x1b[32m.fixture.example.`)
	require.Contains(t, stdout, `bad\x1b[31m.target.example.`)
	finishUDPFixture(t, connection, done)
}

func startUDPFixture(
	t *testing.T,
	reply func(*dns.Msg) *dns.Msg,
) (string, string, net.PacketConn, <-chan error) {
	t.Helper()
	listenConfig := net.ListenConfig{}
	connection, err := listenConfig.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	require.NoError(t, err)
	host, port, err := net.SplitHostPort(connection.LocalAddr().String())
	if err != nil {
		if closeErr := connection.Close(); closeErr != nil {
			t.Errorf("close UDP DNS fixture: %v", closeErr)
		}
		t.Fatal(err)
	}
	return host, port, connection, serveUDPFixtureOnce(connection, reply)
}

func finishUDPFixture(t *testing.T, connection net.PacketConn, done <-chan error) {
	t.Helper()
	require.NoError(t, <-done)
	require.NoError(t, connection.Close(), "close UDP DNS fixture")
}

func serveTCPAnswerFixture(listener net.Listener) <-chan error {
	done := make(chan error, 1)
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err != nil {
			done <- fmt.Errorf("accept TCP DNS fixture connection: %w", err)
			return
		}
		done <- errors.Join(serveTCPAnswer(connection), connection.Close())
	}()
	return done
}

func serveTCPAnswer(connection net.Conn) error {
	lengthBytes := make([]byte, 2)
	if _, err := io.ReadFull(connection, lengthBytes); err != nil {
		return fmt.Errorf("read TCP DNS fixture length: %w", err)
	}
	wire := make([]byte, binary.BigEndian.Uint16(lengthBytes))
	if _, err := io.ReadFull(connection, wire); err != nil {
		return fmt.Errorf("read TCP DNS fixture request: %w", err)
	}
	request := &dns.Msg{Data: wire}
	if err := request.Unpack(); err != nil {
		return fmt.Errorf("unpack TCP DNS fixture request: %w", err)
	}
	response := replyFor(request)
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.Header{Name: "fixture.example.", Class: dns.ClassINET, TTL: 45},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.45")},
	}}
	if err := response.Pack(); err != nil {
		return fmt.Errorf("pack TCP DNS fixture response: %w", err)
	}
	packet := make([]byte, 2+len(response.Data))
	binary.BigEndian.PutUint16(packet, uint16(len(response.Data)))
	copy(packet[2:], response.Data)
	if _, err := connection.Write(packet); err != nil {
		return fmt.Errorf("write TCP DNS fixture response: %w", err)
	}
	return nil
}

func TestDNSDirectUsesConfiguredServersWithoutPublicFallback(t *testing.T) {
	t.Parallel()
	var gotAddress string
	root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
		PlaintextExchange: func(_ context.Context, request *dns.Msg, _ dnsquery.Transport, address string) (*dns.Msg, error) {
			gotAddress = address
			return replyFor(request), nil
		},
		ConfiguredServers: func() ([]string, error) { return []string{"192.0.2.53"}, nil },
	})
	_, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "--resolver", "dns")
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.53:53", gotAddress)
}

func TestDNSConfiguredServersRejectNonUDPSchemesAndUseBareFallback(t *testing.T) {
	t.Parallel()

	for _, configured := range []string{
		"tcp://192.0.2.1:53",
		"tls://192.0.2.1:853",
		"https://192.0.2.1/dns-query",
	} {
		t.Run(configured, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			var transports []dnsquery.Transport
			var addresses []string
			root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
				ConfiguredServers: func() ([]string, error) {
					return []string{configured, "192.0.2.53"}, nil
				},
				PlaintextExchange: func(
					_ context.Context,
					request *dns.Msg,
					transport dnsquery.Transport,
					address string,
				) (*dns.Msg, error) {
					transports = append(transports, transport)
					addresses = append(addresses, address)
					if transport != dnsquery.TransportUDP || address != "192.0.2.53:53" {
						return nil, errTestDNSExchangeFailed
					}
					return replyFor(request), nil
				},
			})
			root.SetContext(ctx)
			_, _, err := executeRootCommandStreams(
				t,
				root,
				"dns", "example.test", "--resolver", "dns", "--select", "values",
			)
			require.NoError(t, err)
			assert.Equal(t, []dnsquery.Transport{dnsquery.TransportUDP}, transports)
			assert.Equal(t, []string{"192.0.2.53:53"}, addresses)
		})
	}
}

func TestDNSExplicitPort53WithoutEndpointUsesConfiguredUDP(t *testing.T) {
	t.Parallel()

	configured := 0
	exchanged := 0
	root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
		ConfiguredServers: func() ([]string, error) {
			configured++
			return []string{"192.0.2.53:53"}, nil
		},
		PlaintextExchange: func(_ context.Context, request *dns.Msg, transport dnsquery.Transport, address string) (*dns.Msg, error) {
			exchanged++
			if transport != dnsquery.TransportUDP || address != "192.0.2.53:53" {
				t.Fatalf("transport=%q address=%q", transport, address)
			}
			return replyFor(request), nil
		},
	})
	_, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "--port", "53", "--select", "values")
	require.NoError(t, err)
	assert.Equal(t, 1, configured, "configured calls")
	assert.Equal(t, 1, exchanged, "exchange calls")
}

func TestDNSDirectAcceptsPTROwnerName(t *testing.T) {
	t.Parallel()
	queryNames := make(chan string, 1)
	host, port, connection, done := startUDPFixture(t, func(request *dns.Msg) *dns.Msg {
		queryNames <- request.Question[0].Header().Name
		response := replyFor(request)
		response.Answer = []dns.RR{&dns.PTR{
			Hdr: dns.Header{Name: "8.2.0.192.in-addr.arpa.", Class: dns.ClassINET, TTL: 30},
			PTR: rdata.PTR{Ptr: "ptr.fixture.example."},
		}}
		return response
	})
	root := newRootCmd()
	stdout, _, err := executeRootCommandStreams(
		t,
		root,
		"dns", "@"+host, "8.2.0.192.in-addr.arpa", "PTR", "--port", port, "--select", "values",
	)
	require.NoError(t, err)
	finishUDPFixture(t, connection, done)
	assert.Equal(t, "8.2.0.192.in-addr.arpa.", <-queryNames, "query name")
	assert.Equal(t, "ptr.fixture.example.\n", stdout)
}

func TestDNSDirectPreservesRcodeAndTXTEscaping(t *testing.T) {
	t.Parallel()
	newRoot := func() *cobra.Command {
		return newRootCmdWithDNSDependencies(dnsquery.Dependencies{
			PlaintextExchange: func(_ context.Context, request *dns.Msg, _ dnsquery.Transport, _ string) (*dns.Msg, error) {
				response := replyFor(request)
				response.Rcode = dns.RcodeNameError
				response.Answer = []dns.RR{&dns.TXT{
					Hdr: dns.Header{Name: "example.test.", Class: dns.ClassINET, TTL: 30},
					TXT: rdata.TXT{Txt: []string{`hello "operator"`, "line\nbreak"}},
				}}
				return response, nil
			},
			ConfiguredServers: func() ([]string, error) { return []string{"192.0.2.53"}, nil },
		})
	}
	jsonOutput, _, err := executeRootCommandStreams(
		t,
		newRoot(),
		"dns", "example.test", "TXT", "--resolver", "dns", "--format", "json",
	)
	require.NoError(t, err)
	assert.Contains(t, jsonOutput, `"status": "NXDOMAIN"`)
	root := newRoot()
	stdout, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "TXT", "--resolver", "dns", "--select", "values")
	require.NoError(t, err)
	assert.Equal(t, `"hello \"operator\"" "line\010break"`+"\n", stdout, "selected TXT value")
	jsonValues, _, err := executeRootCommandStreams(t, newRoot(), "dns", "example.test", "TXT", "--resolver", "dns", "--select", "values", "--format", "json")
	require.NoError(t, err)
	wantJSON, err := json.MarshalIndent([]string{strings.TrimSuffix(stdout, "\n")}, "", "  ")
	require.NoError(t, err)
	if want := string(wantJSON) + "\n"; jsonValues != want {
		t.Errorf("selected TXT JSON = %q, want %q", jsonValues, want)
	}
}

func TestDNSDirectValuesAllowEmptyAnswers(t *testing.T) {
	t.Parallel()
	for _, rcode := range []uint16{dns.RcodeSuccess, dns.RcodeNameError} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			t.Parallel()
			newRoot := func() *cobra.Command {
				return newRootCmdWithDNSDependencies(dnsquery.Dependencies{
					PlaintextExchange: func(_ context.Context, request *dns.Msg, _ dnsquery.Transport, _ string) (*dns.Msg, error) {
						response := replyFor(request)
						response.Rcode = rcode
						return response, nil
					},
					ConfiguredServers: func() ([]string, error) { return []string{"192.0.2.53"}, nil },
				})
			}
			stdout, _, err := executeRootCommandStreams(
				t,
				newRoot(),
				"dns", "missing.example", "--resolver", "dns", "--select", "values",
			)
			require.NoError(t, err)
			assert.Empty(t, stdout)
			jsonOutput, _, err := executeRootCommandStreams(t, newRoot(),
				"dns", "missing.example", "--resolver", "dns", "--select", "values", "--format", "json")
			require.NoError(t, err)
			if jsonOutput != "[]\n" {
				t.Errorf("empty values JSON = %q, want %q", jsonOutput, "[]\n")
			}
		})
	}
}

func TestDNSDirectRejectsMismatchedResponse(t *testing.T) {
	t.Parallel()
	root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
		PlaintextExchange: func(_ context.Context, request *dns.Msg, _ dnsquery.Transport, _ string) (*dns.Msg, error) {
			response := replyFor(request)
			response.Question = dns.NewMsg("other.test", dns.TypeA).Question
			return response, nil
		},
		ConfiguredServers: func() ([]string, error) { return []string{"192.0.2.53"}, nil },
	})
	_, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "--resolver", "dns")
	assert.ErrorIs(t, err, errDNSResponseMismatch)
}

func TestDNSTimeoutAndExchangeErrorsPreserveCause(t *testing.T) {
	t.Parallel()
	t.Run("system timeout", func(t *testing.T) {
		t.Parallel()
		root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
			System: stubSystemResolver{lookupNetIP: func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
				<-ctx.Done()
				return nil, fmt.Errorf("silent DNS server: %w", ctx.Err())
			}},
		})
		_, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "-t", "10ms")
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})
	t.Run("direct exchange", func(t *testing.T) {
		t.Parallel()
		target := errTestDNSExchangeFailed
		root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
			PlaintextExchange: func(context.Context, *dns.Msg, dnsquery.Transport, string) (*dns.Msg, error) { return nil, target },
			ConfiguredServers: func() ([]string, error) { return []string{"192.0.2.53"}, nil },
		})
		_, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "--resolver", "dns")
		assert.ErrorIs(t, err, target)
	})
}

func TestDNSPreparedFailurePreservesOutput(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "output")
	require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
	root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
		System: stubSystemResolver{lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errTestDNSLookupFailed
		}},
	})
	_, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "--output", path)
	require.Error(t, err)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "preserve", string(data), "output file")
}

func TestDNSRestoresCommandContext(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{name: "success", args: []string{"dns", "example.test", "--select", "values"}},
		{name: "output setup error", args: []string{"dns", "example.test", "--output", t.TempDir()}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
				System: stubSystemResolver{lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("192.0.2.30")}, nil
				}},
			})
			original := context.WithValue(t.Context(), dnsTestContextKey{}, test.name)
			root.SetContext(original)
			dnsCommand, _, err := root.Find([]string{"dns"})
			require.NoError(t, err)
			_, _, executeErr := executeRootCommandStreams(t, root, test.args...)
			if test.name == "success" {
				require.NoError(t, executeErr)
			} else {
				require.Error(t, executeErr, "expected output setup error")
			}
			assert.Same(t, original, dnsCommand.Context(), "DNS command context was not restored")
		})
	}
}

type dnsTestContextKey struct{}

func replyFor(request *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	dnsutil.SetReply(response, request)
	response.RecursionAvailable = true
	return response
}
