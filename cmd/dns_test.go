package cmd

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"github.com/spf13/cobra"
)

var (
	errUnexpectedConfiguredServerLookup = errors.New("unexpected configured server lookup")
	errTestDNSExchangeFailed            = errors.New("test DNS exchange failed")
	errTestDNSLookupFailed              = errors.New("test DNS lookup failed")
)

func TestDNSAliasesUseTheSameSyntax(t *testing.T) {
	t.Parallel()
	if aliases := newDNSCmd(defaultDNSDependencies()).Aliases; !slices.Equal(aliases, []string{"dig", "nslookup"}) {
		t.Fatalf("aliases = %q", aliases)
	}
	for _, alias := range []string{"dns", "dig", "nslookup"} {
		t.Run(alias, func(t *testing.T) {
			t.Parallel()
			root := newRootCmdWithDNSDependencies(dnsDependencies{
				system: stubSystemResolver{
					lookupNetIP: func(_ context.Context, network, name string) ([]netip.Addr, error) {
						if network != "ip4" || name != "example.test" {
							t.Fatalf("lookup = %s %q", network, name)
						}
						return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
					},
				},
			})
			stdout, _, err := executeRootCommandStreams(t, root, alias, "example.test", "A", "--short")
			if err != nil || stdout != "192.0.2.1\n" {
				t.Fatalf("output = %q, error = %v", stdout, err)
			}
		})
	}
}

func TestDNSRejectsInvalidOptionsBeforeOpeningOutput(t *testing.T) {
	t.Parallel()
	tests := [][]string{
		{"example.test", "MX"},
		{"@127.0.0.1", "example.test", "--resolver", "system"},
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
			if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
				t.Fatal(err)
			}
			args = append(args, "--output", path)
			if _, _, err := executeRootStreams(t, args...); err == nil {
				t.Fatal("expected error")
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "preserve" {
				t.Fatalf("output = %q, read error = %v", data, err)
			}
		})
	}
}

func TestDNSSystemPTRAndMetadata(t *testing.T) {
	t.Parallel()
	root := newRootCmdWithDNSDependencies(dnsDependencies{system: stubSystemResolver{lookupAddr: func(_ context.Context, address string) ([]string, error) {
		if address != "192.0.2.8" {
			t.Fatalf("address = %q", address)
		}
		return []string{"ptr.example.test."}, nil
	}}})
	stdout, _, err := executeRootCommandStreams(t, root, "dns", "192.0.2.8", "-x", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var result dnsResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	if result.Server != nil || result.Status != nil || result.Answers[0].TTL != nil || result.Answers[0].Value != "ptr.example.test." {
		t.Fatalf("result = %+v", result)
	}
}

func TestDNSSystemResolverIsInjectedPerCommand(t *testing.T) {
	t.Parallel()
	for _, address := range []string{"192.0.2.11", "192.0.2.12"} {
		t.Run(address, func(t *testing.T) {
			t.Parallel()
			root := newRootCmdWithDNSDependencies(dnsDependencies{system: stubSystemResolver{lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr(address)}, nil
			}}})
			stdout, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "--short")
			if err != nil || stdout != address+"\n" {
				t.Fatalf("output = %q, error = %v", stdout, err)
			}
		})
	}
}

func TestDNSDirectRetriesTruncatedUDPOverTCP(t *testing.T) {
	t.Parallel()
	var transports []string
	deps := dnsDependencies{
		exchange: func(_ context.Context, request *dns.Msg, transport, address string) (*dns.Msg, error) {
			transports = append(transports, transport)
			if address != "127.0.0.1:5353" {
				t.Fatalf("address = %q", address)
			}
			response := replyFor(request)
			if transport == dnsTransportUDP {
				response.Truncated = true
				return response, nil
			}
			response.Answer = []dns.RR{&dns.A{
				Hdr: dns.Header{Name: "example.test.", Class: dns.ClassINET, TTL: 60},
				A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.20")},
			}}
			return response, nil
		},
		configuredServers: func() ([]string, error) { return nil, errUnexpectedConfiguredServerLookup },
	}
	root := newRootCmdWithDNSDependencies(deps)
	stdout, _, err := executeRootCommandStreams(t, root, "dns", "@127.0.0.1", "example.test", "--port", "5353", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(transports, []string{"udp", "tcp"}) || !strings.Contains(stdout, `"transport": "tcp"`) || !strings.Contains(stdout, `"ttl": 60`) {
		t.Fatalf("transports = %q, output = %s", transports, stdout)
	}
}

func TestDNSDirectLocalUDPTruncationFallback(t *testing.T) {
	t.Parallel()
	listenConfig := net.ListenConfig{}
	tcpListener, err := listenConfig.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	root := newRootCmd()
	stdout, _, err := executeRootCommandStreams(t, root, "dns", "@"+host, "fixture.example", "--port", port, "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, `"transport": "tcp"`) || !strings.Contains(stdout, `"value": "192.0.2.45"`) {
		t.Fatalf("output = %s", stdout)
	}
	if serveErr := <-udpDone; serveErr != nil {
		t.Fatal(serveErr)
	}
	if serveErr := <-tcpDone; serveErr != nil {
		t.Fatal(serveErr)
	}
	if err := errors.Join(udpConn.Close(), tcpListener.Close()); err != nil {
		t.Fatalf("close DNS fixtures: %v", err)
	}
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
					if !strings.Contains(output, "\t"+recordType+"\t\n") {
						t.Errorf("text output missing empty %s value: %q", recordType, output)
					}
				}
			},
		},
		{
			name: "json",
			args: []string{"--format", "json"},
			check: func(t *testing.T, output string) {
				t.Helper()
				var result dnsResult
				if err := json.Unmarshal([]byte(output), &result); err != nil {
					t.Fatalf("decode JSON output: %v", err)
				}
				assertEmptyDNSAnswerValues(t, result.Answers)
			},
		},
		{
			name: "short",
			args: []string{"--short"},
			check: func(t *testing.T, output string) {
				t.Helper()
				if output != strings.Repeat("\n", 5) {
					t.Fatalf("short output = %q, want five empty values", output)
				}
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
			if err != nil {
				t.Fatal(err)
			}
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

func assertEmptyDNSAnswerValues(t *testing.T, answers []dnsAnswer) {
	t.Helper()
	wantTypes := []string{"OPT", "NXNAME", "IXFR", "AXFR", "ANY"}
	if len(answers) != len(wantTypes) {
		t.Fatalf("answers = %+v, want %d", answers, len(wantTypes))
	}
	for index, answer := range answers {
		if answer.Type != wantTypes[index] || answer.Value != "" {
			t.Errorf("answer %d = %+v, want type %s with empty value", index, answer, wantTypes[index])
		}
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
			root := newRootCmdWithDNSDependencies(dnsDependencies{
				exchange: func(_ context.Context, request *dns.Msg, _, address string) (*dns.Msg, error) {
					gotAddress = address
					return replyFor(request), nil
				},
				configuredServers: func() ([]string, error) { return nil, errUnexpectedConfiguredServerLookup },
			})
			args := []string{"dns", "@" + test.server, "example.test"}
			if test.portFlag != "" {
				args = append(args, "--port", test.portFlag)
			}
			if _, _, err := executeRootCommandStreams(t, root, args...); err != nil {
				t.Fatal(err)
			}
			if gotAddress != test.wantAddress {
				t.Fatalf("exchange address = %q, want %q", gotAddress, test.wantAddress)
			}
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
			if err := os.WriteFile(outputPath, []byte("preserve"), 0o600); err != nil {
				t.Fatal(err)
			}
			exchanged := false
			root := newRootCmdWithDNSDependencies(dnsDependencies{
				exchange: func(_ context.Context, request *dns.Msg, _, _ string) (*dns.Msg, error) {
					exchanged = true
					return replyFor(request), nil
				},
				configuredServers: func() ([]string, error) { return nil, errUnexpectedConfiguredServerLookup },
			})
			args := []string{"dns", "@" + test.server, "example.test", "--output", outputPath}
			if test.portFlag != "" {
				args = append(args, "--port", test.portFlag)
			}
			_, _, err := executeRootCommandStreams(t, root, args...)
			if !errors.Is(err, errInvalidDNSOptions) {
				t.Fatalf("error = %v, want errInvalidDNSOptions", err)
			}
			if exchanged {
				t.Fatal("invalid server port reached DNS exchange")
			}
			contents, readErr := os.ReadFile(outputPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(contents) != "preserve" {
				t.Fatalf("output = %q, want preserved contents", contents)
			}
		})
	}
}

func TestDNSConfiguredServerFailoverDividesRemainingDeadline(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		parent, cancel := context.WithTimeout(t.Context(), 12*time.Second)
		defer cancel()
		query := directDNSQueryForTest()
		var contexts []context.Context
		var remaining []time.Duration
		attempt := 0
		result, err := resolveDirectDNS(parent, &query, dnsDependencies{
			configuredServers: func() ([]string, error) {
				return []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, nil
			},
			exchange: func(ctx context.Context, request *dns.Msg, _, _ string) (*dns.Msg, error) {
				contexts = append(contexts, ctx)
				deadline, ok := ctx.Deadline()
				if !ok {
					t.Fatal("configured-server attempt has no deadline")
				}
				remaining = append(remaining, time.Until(deadline))
				attempt++
				switch attempt {
				case 1:
					time.Sleep(time.Second)
					return nil, errTestDNSExchangeFailed
				case 2:
					time.Sleep(2 * time.Second)
					return nil, errTestDNSExchangeFailed
				default:
					return replyFor(request), nil
				}
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Server == nil || *result.Server != "192.0.2.3:53" {
			t.Fatalf("result server = %v, want final configured server", result.Server)
		}
		wantRemaining := []time.Duration{4 * time.Second, 11 * time.Second / 2, 9 * time.Second}
		if !slices.Equal(remaining, wantRemaining) {
			t.Fatalf("attempt deadlines = %v, want %v", remaining, wantRemaining)
		}
		assertDNSAttemptContextsCanceled(t, contexts)
	})
}

func TestDNSConfiguredServerUDPAndTCPShareAttemptDeadline(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		parent, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		query := directDNSQueryForTest()
		var contexts []context.Context
		var deadlines []time.Time
		result, err := resolveDirectDNS(parent, &query, dnsDependencies{
			configuredServers: func() ([]string, error) { return []string{"192.0.2.1", "192.0.2.2"}, nil },
			exchange: func(ctx context.Context, request *dns.Msg, transport, _ string) (*dns.Msg, error) {
				contexts = append(contexts, ctx)
				deadline, ok := ctx.Deadline()
				if !ok {
					t.Fatal("configured-server attempt has no deadline")
				}
				deadlines = append(deadlines, deadline)
				response := replyFor(request)
				response.Truncated = transport == dnsTransportUDP
				return response, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Transport == nil || *result.Transport != dnsTransportTCP {
			t.Fatalf("transport = %v, want TCP fallback", result.Transport)
		}
		if len(deadlines) != 2 || deadlines[0] != deadlines[1] || time.Until(deadlines[0]) != 5*time.Second {
			t.Fatalf("UDP/TCP deadlines = %v, want shared deadline 5s from now", deadlines)
		}
		assertDNSAttemptContextsCanceled(t, contexts)
	})
}

func TestDNSExplicitServerAndUnlimitedTimeoutBudgets(t *testing.T) {
	t.Parallel()
	t.Run("explicit server gets full budget", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			parent, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			query := directDNSQueryForTest()
			query.server = "192.0.2.1"
			var exchangeContext context.Context
			_, err := resolveDirectDNS(parent, &query, dnsDependencies{
				configuredServers: func() ([]string, error) { return nil, errUnexpectedConfiguredServerLookup },
				exchange: func(ctx context.Context, request *dns.Msg, _, _ string) (*dns.Msg, error) {
					exchangeContext = ctx
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) != 10*time.Second {
						t.Fatalf("explicit-server deadline = %v, present %t", deadline, ok)
					}
					return replyFor(request), nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			assertDNSAttemptContextsCanceled(t, []context.Context{exchangeContext})
		})
	})
	t.Run("zero timeout has no deadline", func(t *testing.T) {
		t.Parallel()
		query := directDNSQueryForTest()
		query.server = "192.0.2.1"
		var exchangeContext context.Context
		_, err := resolveDirectDNS(t.Context(), &query, dnsDependencies{
			configuredServers: func() ([]string, error) { return nil, errUnexpectedConfiguredServerLookup },
			exchange: func(ctx context.Context, request *dns.Msg, _, _ string) (*dns.Msg, error) {
				exchangeContext = ctx
				if deadline, ok := ctx.Deadline(); ok {
					t.Fatalf("zero-timeout exchange deadline = %v, want none", deadline)
				}
				return replyFor(request), nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		assertDNSAttemptContextsCanceled(t, []context.Context{exchangeContext})
	})
}

func directDNSQueryForTest() dnsQuery {
	return dnsQuery{
		resolver: dnsResolverDirect, name: "example.test", record: dnsTypeA,
		transport: dnsTransportUDP, format: dnsFormatText, port: 53, recordType: dns.TypeA,
	}
}

func assertDNSAttemptContextsCanceled(t *testing.T, contexts []context.Context) {
	t.Helper()
	for index, ctx := range contexts {
		if ctx == nil {
			t.Fatalf("attempt %d did not receive a context", index)
		}
		select {
		case <-ctx.Done():
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Errorf("attempt %d context error = %v, want context.Canceled", index, ctx.Err())
			}
		default:
			t.Errorf("attempt %d context remains active after exchange", index)
		}
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
	if !errors.Is(err, errDNSResponseMismatch) {
		t.Fatalf("error = %v", err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(stdout, '\x1b') ||
		!strings.Contains(stdout, `bad\x1b[32m.fixture.example.`) ||
		!strings.Contains(stdout, `bad\x1b[31m.target.example.`) {

		t.Fatalf("unsafe or missing escaped DNS names: %q", stdout)
	}
	finishUDPFixture(t, connection, done)
}

func startUDPFixture(
	t *testing.T,
	reply func(*dns.Msg) *dns.Msg,
) (string, string, net.PacketConn, <-chan error) {
	t.Helper()
	listenConfig := net.ListenConfig{}
	connection, err := listenConfig.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
	if serveErr := <-done; serveErr != nil {
		t.Fatal(serveErr)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("close UDP DNS fixture: %v", err)
	}
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
	root := newRootCmdWithDNSDependencies(dnsDependencies{
		exchange: func(_ context.Context, request *dns.Msg, _, address string) (*dns.Msg, error) {
			gotAddress = address
			return replyFor(request), nil
		},
		configuredServers: func() ([]string, error) { return []string{"192.0.2.53"}, nil },
	})
	if _, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "--resolver", "dns"); err != nil {
		t.Fatal(err)
	}
	if gotAddress != "192.0.2.53:53" {
		t.Fatalf("address = %q", gotAddress)
	}
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
		"dns", "@"+host, "8.2.0.192.in-addr.arpa", "PTR", "--port", port, "--short",
	)
	if err != nil {
		t.Fatal(err)
	}
	finishUDPFixture(t, connection, done)
	if queryName := <-queryNames; queryName != "8.2.0.192.in-addr.arpa." {
		t.Fatalf("query name = %q", queryName)
	}
	if stdout != "ptr.fixture.example.\n" {
		t.Fatalf("output = %q", stdout)
	}
}

func TestDNSDirectPreservesRcodeAndTXTEscaping(t *testing.T) {
	t.Parallel()
	newRoot := func() *cobra.Command {
		return newRootCmdWithDNSDependencies(dnsDependencies{
			exchange: func(_ context.Context, request *dns.Msg, _, _ string) (*dns.Msg, error) {
				response := replyFor(request)
				response.Rcode = dns.RcodeNameError
				response.Answer = []dns.RR{&dns.TXT{
					Hdr: dns.Header{Name: "example.test.", Class: dns.ClassINET, TTL: 30},
					TXT: rdata.TXT{Txt: []string{`hello "operator"`, "line\nbreak"}},
				}}
				return response, nil
			},
			configuredServers: func() ([]string, error) { return []string{"192.0.2.53"}, nil },
		})
	}
	jsonOutput, _, err := executeRootCommandStreams(
		t,
		newRoot(),
		"dns", "example.test", "TXT", "--resolver", "dns", "--format", "json",
	)
	if err != nil || !strings.Contains(jsonOutput, `"status": "NXDOMAIN"`) {
		t.Fatalf("JSON output = %q, error = %v", jsonOutput, err)
	}
	root := newRoot()
	stdout, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "TXT", "--resolver", "dns", "--short")
	if err != nil {
		t.Fatal(err)
	}
	if stdout != `"hello \"operator\"" "line\010break"`+"\n" {
		t.Fatalf("short TXT = %q", stdout)
	}
}

func TestDNSDirectShortAllowsEmptyAnswers(t *testing.T) {
	t.Parallel()
	for _, rcode := range []uint16{dns.RcodeSuccess, dns.RcodeNameError} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			t.Parallel()
			root := newRootCmdWithDNSDependencies(dnsDependencies{
				exchange: func(_ context.Context, request *dns.Msg, _, _ string) (*dns.Msg, error) {
					response := replyFor(request)
					response.Rcode = rcode
					return response, nil
				},
				configuredServers: func() ([]string, error) { return []string{"192.0.2.53"}, nil },
			})
			stdout, _, err := executeRootCommandStreams(
				t,
				root,
				"dns", "missing.example", "--resolver", "dns", "--short",
			)
			if err != nil || stdout != "" {
				t.Fatalf("output = %q, error = %v", stdout, err)
			}
		})
	}
}

func TestDNSDirectRejectsMismatchedResponse(t *testing.T) {
	t.Parallel()
	root := newRootCmdWithDNSDependencies(dnsDependencies{
		exchange: func(_ context.Context, request *dns.Msg, _, _ string) (*dns.Msg, error) {
			response := replyFor(request)
			response.Question = dns.NewMsg("other.test", dns.TypeA).Question
			return response, nil
		},
		configuredServers: func() ([]string, error) { return []string{"192.0.2.53"}, nil },
	})
	_, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "--resolver", "dns")
	if !errors.Is(err, errDNSResponseMismatch) {
		t.Fatalf("error = %v", err)
	}
}

func TestDNSTimeoutAndExchangeErrorsPreserveCause(t *testing.T) {
	t.Parallel()
	t.Run("system timeout", func(t *testing.T) {
		t.Parallel()
		root := newRootCmdWithDNSDependencies(dnsDependencies{system: stubSystemResolver{lookupNetIP: func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
			<-ctx.Done()
			return nil, fmt.Errorf("silent DNS server: %w", ctx.Err())
		}}})
		_, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "--timeout", "10ms")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("direct exchange", func(t *testing.T) {
		t.Parallel()
		target := errTestDNSExchangeFailed
		root := newRootCmdWithDNSDependencies(dnsDependencies{
			exchange:          func(context.Context, *dns.Msg, string, string) (*dns.Msg, error) { return nil, target },
			configuredServers: func() ([]string, error) { return []string{"192.0.2.53"}, nil },
		})
		_, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "--resolver", "dns")
		if !errors.Is(err, target) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestDNSExchangeHonorsCancellation(t *testing.T) {
	t.Parallel()
	listenConfig := net.ListenConfig{}
	server, err := listenConfig.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := server.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close UDP fixture: %v", closeErr)
		}
	})
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		buffer := make([]byte, 512)
		if _, _, readErr := server.ReadFrom(buffer); readErr != nil {
			t.Errorf("read DNS request: %v", readErr)
		}
		cancel()
	}()
	_, err = exchangeDNS(ctx, dns.NewMsg("example.test", dns.TypeA), dnsTransportUDP, server.LocalAddr().String())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

func TestParseConfiguredDNSServers(t *testing.T) {
	t.Parallel()
	servers, err := parseConfiguredDNSServers(strings.NewReader("search example.test\n# comment\nnameserver 192.0.2.53\nnameserver 2001:db8::53 # local\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(servers, []string{"192.0.2.53", "2001:db8::53"}) {
		t.Fatalf("servers = %q", servers)
	}
}

func TestDNSPreparedFailurePreservesOutput(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "output")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := newRootCmdWithDNSDependencies(dnsDependencies{system: stubSystemResolver{lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errTestDNSLookupFailed
	}}})
	if _, _, err := executeRootCommandStreams(t, root, "dns", "example.test", "--output", path); err == nil {
		t.Fatal("expected error")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "preserve" {
		t.Fatalf("output = %q, error = %v", data, err)
	}
}

func TestDNSRestoresCommandContext(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{name: "success", args: []string{"dns", "example.test", "--short"}},
		{name: "output setup error", args: []string{"dns", "example.test", "--output", t.TempDir()}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := newRootCmdWithDNSDependencies(dnsDependencies{
				system: stubSystemResolver{lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("192.0.2.30")}, nil
				}},
			})
			original := context.WithValue(t.Context(), dnsTestContextKey{}, test.name)
			root.SetContext(original)
			dnsCommand, _, err := root.Find([]string{"dns"})
			if err != nil {
				t.Fatal(err)
			}
			_, _, executeErr := executeRootCommandStreams(t, root, test.args...)
			if test.name == "success" && executeErr != nil {
				t.Fatal(executeErr)
			}
			if test.name != "success" && executeErr == nil {
				t.Fatal("expected output setup error")
			}
			if dnsCommand.Context() != original {
				t.Fatal("DNS command context was not restored")
			}
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

func TestDNSConfiguredServerTimeoutLeavesBudgetForNext(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		parent, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		query := directDNSQueryForTest()
		attempts := 0
		result, err := resolveDirectDNS(parent, &query, dnsDependencies{
			configuredServers: func() ([]string, error) { return []string{"192.0.2.1", "192.0.2.2"}, nil },
			exchange: func(ctx context.Context, request *dns.Msg, _, _ string) (*dns.Msg, error) {
				attempts++
				if attempts == 1 {
					<-ctx.Done()
					return nil, fmt.Errorf("silent DNS server: %w", ctx.Err())
				}
				if err := ctx.Err(); err != nil {
					return nil, fmt.Errorf("second DNS server: %w", err)
				}
				return replyFor(request), nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if attempts != 2 || result.Server == nil || *result.Server != "192.0.2.2:53" {
			t.Fatalf("attempts=%d server=%v, want second configured server", attempts, result.Server)
		}
		if err := parent.Err(); err != nil {
			t.Fatalf("parent expired before successful failover: %v", err)
		}
	})
}
