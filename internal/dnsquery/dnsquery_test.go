package dnsquery_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	externalDNS "codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/internal/dnsquery"
)

var (
	errUnexpectedConfiguredServers = errors.New("unexpected configured DNS server lookup")
	errPlaintextExchange           = errors.New("plaintext DNS exchange failed")
)

func TestResolveSystemResultPreservesJSONSchema(t *testing.T) {
	t.Parallel()

	result, err := dnsquery.Resolve(t.Context(), dnsquery.Request{
		Resolver: dnsquery.ResolverSystem,
		Lookup:   "example.test",
		Name:     "example.test",
		Type:     externalDNS.TypeA,
	}, dnsquery.Dependencies{System: systemResolverStub{
		lookupNetIP: func(_ context.Context, network, host string) ([]netip.Addr, error) {
			if network != "ip4" || host != "example.test" {
				t.Fatalf("LookupNetIP(%q, %q)", network, host)
			}
			return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
		},
	}})
	require.NoError(t, err)

	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	want := `{"resolver":"system","server":null,"transport":null,"query_name":"example.test.",` +
		`"query_type":"A","status":null,"id":null,"authoritative":null,"truncated":null,` +
		`"recursion_available":null,"answers":[{"name":"example.test.","type":"A","class":"IN",` +
		`"ttl":null,"value":"192.0.2.10"}]}`
	assert.Equal(t, want, string(encoded))
}

func TestResolveValidatesTypedRequestsIndependently(t *testing.T) {
	t.Parallel()

	port := uint16(53)
	udpEndpoint := mustEndpoint(t, "udp://192.0.2.1")
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	tests := []struct {
		request dnsquery.Request
		name    string
	}{
		{name: "unknown resolver", request: dnsquery.Request{
			Resolver: "other", Lookup: "example.test", Name: "example.test", Type: externalDNS.TypeA,
		}},
		{name: "system endpoint", request: dnsquery.Request{
			Resolver: dnsquery.ResolverSystem, Endpoint: &udpEndpoint,
			Lookup: "example.test", Name: "example.test", Type: externalDNS.TypeA,
		}},
		{name: "system port", request: dnsquery.Request{
			Resolver: dnsquery.ResolverSystem, ConfiguredPort: &port,
			Lookup: "example.test", Name: "example.test", Type: externalDNS.TypeA,
		}},
		{name: "system TLS", request: dnsquery.Request{
			Resolver: dnsquery.ResolverSystem, Lookup: "example.test", Name: "example.test",
			Type: externalDNS.TypeA, TLSConfig: tlsConfig,
		}},
		{name: "plaintext TLS", request: dnsquery.Request{
			Resolver: dnsquery.ResolverDirect, Endpoint: &udpEndpoint,
			Lookup: "example.test", Name: "example.test", Type: externalDNS.TypeA, TLSConfig: tlsConfig,
		}},
		{name: "missing lookup", request: dnsquery.Request{Resolver: dnsquery.ResolverDirect, Endpoint: &udpEndpoint, Name: "example.test", Type: externalDNS.TypeA}},
		{name: "missing name", request: dnsquery.Request{Resolver: dnsquery.ResolverDirect, Endpoint: &udpEndpoint, Lookup: "example.test", Type: externalDNS.TypeA}},
		{name: "zero type", request: dnsquery.Request{Resolver: dnsquery.ResolverDirect, Endpoint: &udpEndpoint, Lookup: "example.test", Name: "example.test"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := dnsquery.Resolve(t.Context(), test.request, dnsquery.Dependencies{})
			assert.ErrorIs(t, err, dnsquery.ErrInvalidRequest)
		})
	}
}

func TestParseEndpointPortAgreement(t *testing.T) {
	t.Parallel()

	port53 := uint16(53)
	port5353 := uint16(5353)
	tests := []struct {
		name         string
		raw          string
		explicitPort *uint16
		wantAddress  string
		wantErr      bool
	}{
		{name: "bare default", raw: "192.0.2.1", wantAddress: "192.0.2.1:53"},
		{name: "bare explicit 53", raw: "192.0.2.1", explicitPort: &port53, wantAddress: "192.0.2.1:53"},
		{name: "UDP inline agrees with explicit 53", raw: "udp://192.0.2.1:53", explicitPort: &port53, wantAddress: "192.0.2.1:53"},
		{name: "TCP inline preserved", raw: "tcp://192.0.2.1:5353", wantAddress: "192.0.2.1:5353"},
		{name: "TLS default", raw: "tls://resolver.example", wantAddress: "resolver.example:853"},
		{name: "HTTPS default", raw: "https://resolver.example/dns-query", wantAddress: "resolver.example:443"},
		{name: "inline conflicts with explicit", raw: "udp://192.0.2.1:53", explicitPort: &port5353, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			endpoint, err := dnsquery.ParseEndpoint(test.raw, test.explicitPort)
			if test.wantErr {
				assert.ErrorIs(t, err, dnsquery.ErrInvalidEndpoint)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.wantAddress, endpoint.Address())
		})
	}
}

func TestResolveConfiguredUDPExplicitPort53(t *testing.T) {
	t.Parallel()

	port := uint16(53)
	var calls int
	result, err := dnsquery.Resolve(t.Context(), dnsquery.Request{
		Resolver:       dnsquery.ResolverDirect,
		ConfiguredPort: &port,
		Lookup:         "example.test",
		Name:           "example.test",
		Type:           externalDNS.TypeA,
	}, dnsquery.Dependencies{
		ConfiguredServers: func() ([]string, error) { return []string{"192.0.2.53:53"}, nil },
		PlaintextExchange: func(_ context.Context, request *externalDNS.Msg, transport dnsquery.Transport, address string) (*externalDNS.Msg, error) {
			calls++
			if transport != dnsquery.TransportUDP || address != "192.0.2.53:53" {
				t.Fatalf("exchange transport=%q address=%q", transport, address)
			}
			return replyFor(request), nil
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
	require.NotNil(t, result.Server)
	assert.Equal(t, "192.0.2.53:53", *result.Server)
	require.NotNil(t, result.Transport)
	assert.Equal(t, dnsquery.TransportUDP, *result.Transport)
}

func TestResolveConfiguredPortConflictPreventsExchange(t *testing.T) {
	t.Parallel()

	port := uint16(53)
	exchanged := false
	_, err := dnsquery.Resolve(t.Context(), dnsquery.Request{
		Resolver:       dnsquery.ResolverDirect,
		ConfiguredPort: &port,
		Lookup:         "example.test",
		Name:           "example.test",
		Type:           externalDNS.TypeA,
	}, dnsquery.Dependencies{
		ConfiguredServers: func() ([]string, error) { return []string{"192.0.2.53:5353"}, nil },
		PlaintextExchange: func(context.Context, *externalDNS.Msg, dnsquery.Transport, string) (*externalDNS.Msg, error) {
			exchanged = true
			return nil, nil //nolint:nilnil // A nil peer response is the protocol boundary under test.
		},
	})
	require.ErrorIs(t, err, dnsquery.ErrInvalidEndpoint)
	assert.False(t, exchanged, "conflicting configured port reached exchange")
}

func TestResolveConfiguredServersSkipsMalformedEntries(t *testing.T) {
	t.Parallel()

	exchanged := 0
	result, err := dnsquery.Resolve(t.Context(), configuredRequest(), dnsquery.Dependencies{
		ConfiguredServers: func() ([]string, error) {
			return []string{"malformed:server:entry", "192.0.2.53"}, nil
		},
		PlaintextExchange: func(_ context.Context, request *externalDNS.Msg, transport dnsquery.Transport, address string) (*externalDNS.Msg, error) {
			exchanged++
			if transport != dnsquery.TransportUDP || address != "192.0.2.53:53" {
				t.Fatalf("transport=%q address=%q", transport, address)
			}
			return replyFor(request), nil
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, exchanged)
	require.NotNil(t, result.Server)
	assert.Equal(t, "192.0.2.53:53", *result.Server)
}

func TestResolveConfiguredServersRejectsNonUDPSchemesAndUsesBareFallback(t *testing.T) {
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
			var exchanges []struct {
				transport dnsquery.Transport
				address   string
			}
			result, err := dnsquery.Resolve(ctx, configuredRequest(), dnsquery.Dependencies{
				ConfiguredServers: func() ([]string, error) {
					return []string{configured, "192.0.2.53"}, nil
				},
				PlaintextExchange: func(
					_ context.Context,
					request *externalDNS.Msg,
					transport dnsquery.Transport,
					address string,
				) (*externalDNS.Msg, error) {
					exchanges = append(exchanges, struct {
						transport dnsquery.Transport
						address   string
					}{transport: transport, address: address})
					if transport != dnsquery.TransportUDP || address != "192.0.2.53:53" {
						return nil, errPlaintextExchange
					}
					return replyFor(request), nil
				},
			})
			require.NoError(t, err)
			validFallback := len(exchanges) == 1 &&
				exchanges[0].transport == dnsquery.TransportUDP &&
				exchanges[0].address == "192.0.2.53:53"
			if !validFallback {
				t.Fatalf("exchanges = %+v", exchanges)
			}
			require.NotNil(t, result.Server)
			require.Equal(t, "192.0.2.53:53", *result.Server)
		})
	}
}

func TestResolveAllConfiguredNonUDPSchemesPreserveInvalidEndpoint(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	exchanges := 0
	_, err := dnsquery.Resolve(ctx, configuredRequest(), dnsquery.Dependencies{
		ConfiguredServers: func() ([]string, error) {
			return []string{
				"tcp://192.0.2.1:53",
				"tls://192.0.2.1:853",
				"https://192.0.2.1/dns-query",
			}, nil
		},
		PlaintextExchange: func(context.Context, *externalDNS.Msg, dnsquery.Transport, string) (*externalDNS.Msg, error) {
			exchanges++
			return nil, errPlaintextExchange
		},
	})
	require.ErrorIs(t, err, dnsquery.ErrInvalidEndpoint)
	assert.Zero(t, exchanges, "plaintext exchanges")
}

func TestResolveRejectsMutatedEndpoint(t *testing.T) {
	t.Parallel()

	endpoint := dnsquery.Endpoint{Transport: dnsquery.TransportHTTPS}
	_, err := dnsquery.Resolve(t.Context(), dnsquery.Request{
		Resolver:  dnsquery.ResolverDirect,
		Endpoint:  &endpoint,
		Lookup:    "example.test",
		Name:      "example.test",
		Type:      externalDNS.TypeA,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}, dnsquery.Dependencies{})
	if !errors.Is(err, dnsquery.ErrInvalidRequest) && !errors.Is(err, dnsquery.ErrInvalidEndpoint) {
		t.Fatalf("error = %v, want invalid request or endpoint", err)
	}
}

func TestResolveNilRDATAProducesEmptyValues(t *testing.T) {
	t.Parallel()

	endpoint := mustEndpoint(t, "192.0.2.1")
	result, err := dnsquery.Resolve(t.Context(), directRequest(endpoint), dnsquery.Dependencies{
		ConfiguredServers: func() ([]string, error) { return nil, errUnexpectedConfiguredServers },
		PlaintextExchange: func(_ context.Context, request *externalDNS.Msg, _ dnsquery.Transport, _ string) (*externalDNS.Msg, error) {
			response := replyFor(request)
			header := externalDNS.Header{Name: "example.test.", Class: externalDNS.ClassINET, TTL: 30}
			response.Answer = []externalDNS.RR{
				&externalDNS.OPT{Hdr: header},
				&externalDNS.NXNAME{Hdr: header},
				&externalDNS.IXFR{Hdr: header},
				&externalDNS.AXFR{Hdr: header},
				&externalDNS.ANY{Hdr: header},
			}
			return response, nil
		},
	})
	require.NoError(t, err)
	wantTypes := []string{"OPT", "NXNAME", "IXFR", "AXFR", "ANY"}
	require.Len(t, result.Answers, len(wantTypes))
	for index, answer := range result.Answers {
		assert.Equal(t, wantTypes[index], answer.Type, "answer %d", index)
		assert.Empty(t, answer.Value, "answer %d", index)
	}
}

func TestResolveRejectsMismatchedResponses(t *testing.T) {
	t.Parallel()

	endpoint := mustEndpoint(t, "192.0.2.1")
	tests := []struct {
		mutate func(*externalDNS.Msg)
		name   string
	}{
		{name: "nil", mutate: nil},
		{name: "query bit", mutate: func(response *externalDNS.Msg) { response.Response = false }},
		{name: "ID", mutate: func(response *externalDNS.Msg) { response.ID++ }},
		{name: "opcode", mutate: func(response *externalDNS.Msg) { response.Opcode = externalDNS.OpcodeUpdate }},
		{name: "question", mutate: func(response *externalDNS.Msg) {
			response.Question = externalDNS.NewMsg("other.test", externalDNS.TypeA).Question
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := dnsquery.Resolve(t.Context(), directRequest(endpoint), dnsquery.Dependencies{
				ConfiguredServers: func() ([]string, error) { return nil, errUnexpectedConfiguredServers },
				PlaintextExchange: func(_ context.Context, request *externalDNS.Msg, _ dnsquery.Transport, _ string) (*externalDNS.Msg, error) {
					if test.mutate == nil {
						return nil, nil //nolint:nilnil // A nil peer response must map to ErrResponseMismatch.
					}
					response := replyFor(request)
					test.mutate(response)
					return response, nil
				},
			})
			require.ErrorIs(t, err, dnsquery.ErrResponseMismatch)
		})
	}
}

func TestResolveConfiguredFailoverDividesRemainingBudget(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		parent, cancel := context.WithTimeout(t.Context(), 12*time.Second)
		defer cancel()
		var contexts []context.Context
		var remaining []time.Duration
		attempt := 0
		result, err := dnsquery.Resolve(parent, configuredRequest(), dnsquery.Dependencies{
			ConfiguredServers: func() ([]string, error) {
				return []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, nil
			},
			PlaintextExchange: func(ctx context.Context, request *externalDNS.Msg, _ dnsquery.Transport, _ string) (*externalDNS.Msg, error) {
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
					return nil, errPlaintextExchange
				case 2:
					time.Sleep(2 * time.Second)
					return nil, errPlaintextExchange
				default:
					return replyFor(request), nil
				}
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result.Server)
		require.Equal(t, "192.0.2.3:53", *result.Server)
		wantRemaining := []time.Duration{4 * time.Second, 11 * time.Second / 2, 9 * time.Second}
		require.Equal(t, wantRemaining, remaining, "attempt deadlines")
		assertContextsCanceled(t, contexts)
	})
}

func TestResolveUDPAndTCPFallbackShareAttemptBudget(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		parent, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		var contexts []context.Context
		var deadlines []time.Time
		result, err := dnsquery.Resolve(parent, configuredRequest(), dnsquery.Dependencies{
			ConfiguredServers: func() ([]string, error) { return []string{"192.0.2.1", "192.0.2.2"}, nil },
			PlaintextExchange: func(ctx context.Context, request *externalDNS.Msg, transport dnsquery.Transport, _ string) (*externalDNS.Msg, error) {
				contexts = append(contexts, ctx)
				deadline, ok := ctx.Deadline()
				if !ok {
					t.Fatal("configured-server attempt has no deadline")
				}
				deadlines = append(deadlines, deadline)
				response := replyFor(request)
				response.Truncated = transport == dnsquery.TransportUDP
				return response, nil
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result.Transport)
		require.Equal(t, dnsquery.TransportTCP, *result.Transport)
		if len(deadlines) != 2 || deadlines[0] != deadlines[1] || time.Until(deadlines[0]) != 5*time.Second {
			t.Fatalf("UDP/TCP deadlines = %v", deadlines)
		}
		assertContextsCanceled(t, contexts)
	})
}

func TestResolveConfiguredTimeoutLeavesBudgetForNextServer(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		parent, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		attempts := 0
		result, err := dnsquery.Resolve(parent, configuredRequest(), dnsquery.Dependencies{
			ConfiguredServers: func() ([]string, error) { return []string{"192.0.2.1", "192.0.2.2"}, nil },
			PlaintextExchange: func(ctx context.Context, request *externalDNS.Msg, _ dnsquery.Transport, _ string) (*externalDNS.Msg, error) {
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
		require.NoError(t, err)
		if attempts != 2 || result.Server == nil || *result.Server != "192.0.2.2:53" {
			t.Fatalf("attempts=%d server=%v", attempts, result.Server)
		}
		if err := parent.Err(); err != nil {
			t.Fatalf("parent expired before successful failover: %v", err)
		}
	})
}

func TestResolveExplicitEndpointUsesWholeContextBudget(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		parent, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		endpoint := mustEndpoint(t, "192.0.2.1")
		var exchangeContext context.Context
		_, err := dnsquery.Resolve(parent, directRequest(endpoint), dnsquery.Dependencies{
			ConfiguredServers: func() ([]string, error) { return nil, errUnexpectedConfiguredServers },
			PlaintextExchange: func(ctx context.Context, request *externalDNS.Msg, _ dnsquery.Transport, _ string) (*externalDNS.Msg, error) {
				exchangeContext = ctx
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) != 10*time.Second {
					t.Fatalf("explicit endpoint deadline=%v present=%t", deadline, ok)
				}
				return replyFor(request), nil
			},
		})
		require.NoError(t, err)
		assertContextsCanceled(t, []context.Context{exchangeContext})
	})
}

func TestResolveWithoutDeadlineDoesNotInventOne(t *testing.T) {
	t.Parallel()

	endpoint := mustEndpoint(t, "192.0.2.1")
	var exchangeContext context.Context
	_, err := dnsquery.Resolve(t.Context(), directRequest(endpoint), dnsquery.Dependencies{
		ConfiguredServers: func() ([]string, error) { return nil, errUnexpectedConfiguredServers },
		PlaintextExchange: func(ctx context.Context, request *externalDNS.Msg, _ dnsquery.Transport, _ string) (*externalDNS.Msg, error) {
			exchangeContext = ctx
			if deadline, ok := ctx.Deadline(); ok {
				t.Fatalf("exchange deadline = %v, want none", deadline)
			}
			return replyFor(request), nil
		},
	})
	require.NoError(t, err)
	assertContextsCanceled(t, []context.Context{exchangeContext})
}

func TestResolvePlaintextExchangeHonorsCancellation(t *testing.T) {
	t.Parallel()

	server, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	require.NoError(t, err)
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
	endpoint := mustEndpoint(t, server.LocalAddr().String())
	_, err = dnsquery.Resolve(ctx, directRequest(endpoint), dnsquery.DefaultDependencies())
	require.ErrorIs(t, err, context.Canceled)
}

func TestResolveDoHRejectsRedirects(t *testing.T) {
	t.Parallel()

	var redirectedRequests int
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectedRequests++
	}))
	t.Cleanup(target.Close)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(server.Close)

	endpoint := mustEndpoint(t, server.URL+"/dns-query")
	transport, ok := server.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("test server transport type = %T", server.Client().Transport)
	}
	config := transport.TLSClientConfig.Clone()
	_, err := dnsquery.Resolve(t.Context(), dnsquery.Request{
		Resolver:  dnsquery.ResolverDirect,
		Endpoint:  &endpoint,
		Lookup:    "example.test",
		Name:      "example.test",
		Type:      externalDNS.TypeA,
		TLSConfig: config,
	}, dnsquery.Dependencies{})
	require.Error(t, err, "DoH redirect succeeded")
	assert.Zero(t, redirectedRequests, "redirect target requests")
}

func TestResolveClonesTLSConfigBeforeDefaultingServerName(t *testing.T) {
	t.Parallel()

	endpoint := mustEndpoint(t, "tls://127.0.0.1:1")
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	_, err := dnsquery.Resolve(t.Context(), dnsquery.Request{
		Resolver:  dnsquery.ResolverDirect,
		Endpoint:  &endpoint,
		Lookup:    "example.test",
		Name:      "example.test",
		Type:      externalDNS.TypeA,
		TLSConfig: config,
	}, dnsquery.Dependencies{})
	require.Error(t, err, "closed DoT endpoint succeeded")
	assert.Empty(t, config.ServerName, "caller TLS ServerName must not be mutated")
}

func TestResolveDoTConnectionRefusedDoesNotRetry(t *testing.T) {
	t.Parallel()

	reservation, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := reservation.Addr().String()
	require.NoError(t, reservation.Close())
	endpoint := mustEndpoint(t, "tls://"+address)
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()

	_, err = dnsquery.Resolve(ctx, dnsquery.Request{
		Resolver:  dnsquery.ResolverDirect,
		Endpoint:  &endpoint,
		Lookup:    "example.test",
		Name:      "example.test",
		Type:      externalDNS.TypeA,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}, dnsquery.Dependencies{})
	require.ErrorIs(t, err, syscall.ECONNREFUSED)
	assert.NoError(t, ctx.Err(), "DoT connection refusal must not exhaust caller context")
}

func TestResolveDoTPreservesCanceledContext(t *testing.T) {
	t.Parallel()

	endpoint := mustEndpoint(t, "tls://127.0.0.1:1")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := dnsquery.Resolve(ctx, dnsquery.Request{
		Resolver:  dnsquery.ResolverDirect,
		Endpoint:  &endpoint,
		Lookup:    "example.test",
		Name:      "example.test",
		Type:      externalDNS.TypeA,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}, dnsquery.Dependencies{})
	require.ErrorIs(t, err, context.Canceled)
}

func TestResolveDependencyErrorsPreserveIdentity(t *testing.T) {
	t.Parallel()

	endpoint := mustEndpoint(t, "192.0.2.1")
	_, err := dnsquery.Resolve(t.Context(), directRequest(endpoint), dnsquery.Dependencies{
		ConfiguredServers: func() ([]string, error) { return nil, errUnexpectedConfiguredServers },
		PlaintextExchange: func(context.Context, *externalDNS.Msg, dnsquery.Transport, string) (*externalDNS.Msg, error) {
			return nil, errPlaintextExchange
		},
	})
	require.ErrorIs(t, err, errPlaintextExchange)

	_, err = dnsquery.Resolve(t.Context(), configuredRequest(), dnsquery.Dependencies{
		ConfiguredServers: func() ([]string, error) { return nil, errUnexpectedConfiguredServers },
		PlaintextExchange: func(context.Context, *externalDNS.Msg, dnsquery.Transport, string) (*externalDNS.Msg, error) {
			return nil, errPlaintextExchange
		},
	})
	require.ErrorIs(t, err, errUnexpectedConfiguredServers)
}

func TestCoreHasNoCobraOrCmdImports(t *testing.T) {
	t.Parallel()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	directory := filepath.Dir(filename)
	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		require.NoError(t, err)
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			require.NoError(t, err)
			if importPath == "github.com/spf13/cobra" || strings.HasSuffix(importPath, "/cmd") {
				t.Errorf("%s imports %q", entry.Name(), importPath)
			}
		}
	}
}

func directRequest(endpoint dnsquery.Endpoint) dnsquery.Request {
	return dnsquery.Request{
		Resolver: dnsquery.ResolverDirect,
		Endpoint: &endpoint,
		Lookup:   "example.test",
		Name:     "example.test",
		Type:     externalDNS.TypeA,
	}
}

func configuredRequest() dnsquery.Request {
	return dnsquery.Request{
		Resolver: dnsquery.ResolverDirect,
		Lookup:   "example.test",
		Name:     "example.test",
		Type:     externalDNS.TypeA,
	}
}

func mustEndpoint(t *testing.T, raw string) dnsquery.Endpoint {
	t.Helper()
	endpoint, err := dnsquery.ParseEndpoint(raw, nil)
	require.NoError(t, err)
	return endpoint
}

func replyFor(request *externalDNS.Msg) *externalDNS.Msg {
	response := new(externalDNS.Msg)
	dnsutil.SetReply(response, request)
	response.RecursionAvailable = true
	return response
}

func assertContextsCanceled(t *testing.T, contexts []context.Context) {
	t.Helper()
	for index, ctx := range contexts {
		if ctx == nil {
			t.Fatalf("attempt %d received a nil context", index)
		}
		select {
		case <-ctx.Done():
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Errorf("attempt %d context error = %v", index, ctx.Err())
			}
		default:
			t.Errorf("attempt %d context remains active", index)
		}
	}
}

type systemResolverStub struct {
	lookupNetIP func(context.Context, string, string) ([]netip.Addr, error)
	lookupAddr  func(context.Context, string) ([]string, error)
}

func (resolver systemResolverStub) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if resolver.lookupNetIP == nil {
		return nil, fmt.Errorf("LookupNetIP: %w", dnsquery.ErrResolverUnavailable)
	}
	return resolver.lookupNetIP(ctx, network, host)
}

func (resolver systemResolverStub) LookupAddr(ctx context.Context, address string) ([]string, error) {
	if resolver.lookupAddr == nil {
		return nil, fmt.Errorf("LookupAddr: %w", dnsquery.ErrResolverUnavailable)
	}
	return resolver.lookupAddr(ctx, address)
}
