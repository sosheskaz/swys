// Package dnsquery resolves DNS queries through system, plaintext, TLS, and HTTPS transports.
package dnsquery

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	externalDNS "codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/sosheskaz/swys/internal/netconn"
)

// Resolver identifies the source used to resolve a query.
type Resolver string

// Transport identifies a direct DNS transport.
type Transport string

// Resolver and transport values accepted by Request.
const (
	ResolverSystem      Resolver  = "system"
	ResolverDirect      Resolver  = "dns"
	TransportUDP        Transport = "udp"
	TransportTCP        Transport = "tcp"
	TransportTLS        Transport = "tls"
	TransportHTTPS      Transport = "https"
	dnsMessageMediaType           = "application/dns-message"
)

var (
	// ErrInvalidRequest indicates an internally inconsistent request.
	ErrInvalidRequest = errors.New("invalid DNS request")
	// ErrInvalidEndpoint indicates an invalid direct resolver endpoint.
	ErrInvalidEndpoint = errors.New("invalid DNS endpoint")
	// ErrResponseMismatch indicates a response that does not match its query.
	ErrResponseMismatch = errors.New("DNS response does not match query")
	// ErrNoConfiguredServer indicates that the host has no configured DNS server.
	ErrNoConfiguredServer = errors.New("no configured DNS servers found")
	// ErrResolverUnavailable indicates a missing resolver dependency.
	ErrResolverUnavailable = errors.New("DNS resolver is unavailable")
	errDoHStatus           = errors.New("unexpected DoH status")
	errDoHContentType      = errors.New("invalid DoH content type")
	errDoHResponseTooLarge = errors.New("DoH response too large")
)

// Endpoint is a validated direct resolver endpoint.
type Endpoint struct {
	Transport       Transport
	address         string
	dohURL          *url.URL
	parsedTransport Transport
}

// Address returns the endpoint's normalized host and port.
func (e Endpoint) Address() string { return e.address }

// Request describes one DNS lookup.
type Request struct { //nolint:govet // Field order follows request semantics and the public contract.
	Resolver       Resolver
	Endpoint       *Endpoint
	ConfiguredPort *uint16
	Lookup         string
	Name           string
	Type           uint16
	TLSConfig      *tls.Config
}

// SystemResolver is the subset of net.Resolver used for system lookups.
type SystemResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// PlaintextExchange exchanges a DNS message over UDP or TCP.
type PlaintextExchange func(context.Context, *externalDNS.Msg, Transport, string) (*externalDNS.Msg, error)

// Dependencies supplies host and network integrations.
type Dependencies struct {
	System            SystemResolver
	ConfiguredServers func() ([]string, error)
	PlaintextExchange PlaintextExchange
}

// Answer is one normalized DNS answer.
type Answer struct {
	Name  string  `json:"name"`
	Type  string  `json:"type"`
	Class string  `json:"class"`
	TTL   *uint32 `json:"ttl"`
	Value string  `json:"value"`
}

// Result is the resolver-independent representation rendered by the command.
type Result struct {
	Resolver           Resolver   `json:"resolver"`
	Server             *string    `json:"server"`
	Transport          *Transport `json:"transport"`
	QueryName          string     `json:"query_name"`
	QueryType          string     `json:"query_type"`
	Status             *string    `json:"status"`
	ID                 *uint16    `json:"id"`
	Authoritative      *bool      `json:"authoritative"`
	Truncated          *bool      `json:"truncated"`
	RecursionAvailable *bool      `json:"recursion_available"`
	Answers            []Answer   `json:"answers"`
}

// DefaultDependencies returns the production resolver integrations.
func DefaultDependencies() Dependencies {
	return Dependencies{System: net.DefaultResolver, ConfiguredServers: configuredDNSServers, PlaintextExchange: exchangePlaintext}
}

// ParseEndpoint validates and normalizes a direct resolver endpoint.
func ParseEndpoint(raw string, explicitPort *uint16) (Endpoint, error) {
	if raw == "" || explicitPort != nil && *explicitPort == 0 {
		return Endpoint{}, fmt.Errorf("%w: empty endpoint or zero port", ErrInvalidEndpoint)
	}
	transport, host, parsed, err := parseEndpointURL(raw)
	if err != nil {
		return Endpoint{}, err
	}
	defaultPort := uint16(53)
	if transport == TransportTLS {
		defaultPort = 853
	}
	if transport == TransportHTTPS {
		defaultPort = 443
	}
	address, err := normalizeAddress(host, defaultPort, explicitPort)
	if err != nil {
		return Endpoint{}, err
	}
	if transport != TransportHTTPS {
		parsed = nil
	}
	return Endpoint{Transport: transport, address: address, dohURL: parsed, parsedTransport: transport}, nil
}

func parseEndpointURL(raw string) (Transport, string, *url.URL, error) {
	if !strings.Contains(raw, "://") {
		if strings.ContainsAny(raw, "/?#@") {
			return "", "", nil, ErrInvalidEndpoint
		}
		return TransportUDP, raw, nil, nil
	}
	if strings.Contains(raw, "#") {
		return "", "", nil, fmt.Errorf("%w: fragments are not allowed", ErrInvalidEndpoint)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", nil, fmt.Errorf("%w: %w", ErrInvalidEndpoint, err)
	}
	transport := Transport(u.Scheme)
	if !validTransport(transport) {
		return "", "", nil, fmt.Errorf("%w: unsupported scheme", ErrInvalidEndpoint)
	}
	if err := validateEndpointURL(u, transport); err != nil {
		return "", "", nil, err
	}
	if transport == TransportHTTPS && u.Path == "" {
		u.Path = "/dns-query"
	}
	return transport, u.Host, u, nil
}

func validTransport(transport Transport) bool {
	return transport == TransportUDP || transport == TransportTCP ||
		transport == TransportTLS || transport == TransportHTTPS
}

func validateEndpointURL(endpoint *url.URL, transport Transport) error {
	if endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Fragment != "" {
		return ErrInvalidEndpoint
	}
	if transport != TransportHTTPS && (endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.ForceQuery) {
		return ErrInvalidEndpoint
	}
	return nil
}

func normalizeAddress(raw string, defaultPort uint16, explicit *uint16) (string, error) {
	if host, portText, err := net.SplitHostPort(raw); err == nil {
		if host == "" {
			return "", ErrInvalidEndpoint
		}
		if _, hostErr := endpointHost(host); hostErr != nil {
			return "", hostErr
		}
		port, e := strconv.ParseUint(portText, 10, 16)
		if e != nil || port == 0 {
			return "", ErrInvalidEndpoint
		}
		if explicit != nil && port != uint64(*explicit) {
			return "", ErrInvalidEndpoint
		}
		return net.JoinHostPort(host, strconv.FormatUint(port, 10)), nil
	}
	host, err := endpointHost(raw)
	if err != nil {
		return "", err
	}
	port := defaultPort
	if explicit != nil {
		port = *explicit
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func endpointHost(raw string) (string, error) {
	if raw == "" {
		return "", ErrInvalidEndpoint
	}
	if !strings.ContainsAny(raw, "[]") {
		if !strings.Contains(raw, ":") {
			return raw, nil
		}
		address, err := netip.ParseAddr(raw)
		if err != nil || !address.Is6() {
			return "", ErrInvalidEndpoint
		}
		return raw, nil
	}
	if strings.Count(raw, "[") != 1 || strings.Count(raw, "]") != 1 || !strings.HasPrefix(raw, "[") || !strings.HasSuffix(raw, "]") {
		return "", ErrInvalidEndpoint
	}
	host := strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
	if host == "" {
		return "", ErrInvalidEndpoint
	}
	if strings.Contains(host, ":") {
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is6() {
			return "", ErrInvalidEndpoint
		}
	}
	return host, nil
}

// Resolve executes a validated DNS request.
//
//nolint:gocritic // Value input keeps ownership explicit at the package boundary.
func Resolve(ctx context.Context, request Request, deps Dependencies) (Result, error) {
	if err := validateRequest(&request); err != nil {
		return Result{}, err
	}
	if request.Resolver == ResolverSystem {
		return resolveSystem(ctx, &request, deps.System)
	}
	return resolveDirect(ctx, &request, deps)
}

func validateRequest(r *Request) error {
	if r.Lookup == "" || r.Name == "" || r.Type == 0 {
		return ErrInvalidRequest
	}
	if r.Resolver == ResolverSystem {
		return validateSystemRequest(r)
	}
	if r.Resolver != ResolverDirect {
		return ErrInvalidRequest
	}
	return validateDirectRequest(r)
}

func validateSystemRequest(r *Request) error {
	if r.Endpoint != nil || r.ConfiguredPort != nil || r.TLSConfig != nil {
		return ErrInvalidRequest
	}
	return nil
}

func validateDirectRequest(r *Request) error {
	if r.Endpoint != nil && r.ConfiguredPort != nil {
		return ErrInvalidRequest
	}
	if r.ConfiguredPort != nil && *r.ConfiguredPort == 0 {
		return ErrInvalidRequest
	}
	if r.Endpoint != nil {
		if err := validateEndpoint(*r.Endpoint); err != nil {
			return err
		}
	}
	if r.Endpoint == nil || r.Endpoint.Transport == TransportUDP || r.Endpoint.Transport == TransportTCP {
		if r.TLSConfig != nil {
			return ErrInvalidRequest
		}
	} else if r.TLSConfig == nil {
		return ErrInvalidRequest
	}
	return nil
}

func validateEndpoint(endpoint Endpoint) error {
	if !validTransport(endpoint.Transport) || endpoint.Transport != endpoint.parsedTransport || endpoint.address == "" {
		return ErrInvalidEndpoint
	}
	if endpoint.Transport == TransportHTTPS {
		if endpoint.dohURL == nil {
			return ErrInvalidEndpoint
		}
	} else if endpoint.dohURL != nil {
		return ErrInvalidEndpoint
	}
	host, port, err := net.SplitHostPort(endpoint.address)
	if err != nil || host == "" {
		return ErrInvalidEndpoint
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return ErrInvalidEndpoint
	}
	return nil
}

func resolveSystem(ctx context.Context, r *Request, res SystemResolver) (Result, error) {
	if res == nil {
		return Result{}, fmt.Errorf("%w: system", ErrResolverUnavailable)
	}
	typeName := externalDNS.TypeToString[r.Type]
	result := Result{Resolver: ResolverSystem, QueryName: dnsutil.Fqdn(r.Name), QueryType: typeName, Answers: []Answer{}}
	switch r.Type {
	case externalDNS.TypeA, externalDNS.TypeAAAA:
		network := "ip4"
		if r.Type == externalDNS.TypeAAAA {
			network = "ip6"
		}
		addrs, err := res.LookupNetIP(ctx, network, r.Lookup)
		if err != nil {
			return Result{}, fmt.Errorf("system address lookup: %w", err)
		}
		for _, a := range addrs {
			result.Answers = append(result.Answers, Answer{Name: dnsutil.Fqdn(r.Lookup), Type: typeName, Class: "IN", Value: a.String()})
		}
	case externalDNS.TypePTR:
		names, err := res.LookupAddr(ctx, r.Lookup)
		if err != nil {
			return Result{}, fmt.Errorf("system reverse lookup: %w", err)
		}
		for _, n := range names {
			result.Answers = append(result.Answers, Answer{Name: r.Name, Type: typeName, Class: "IN", Value: dnsutil.Fqdn(n)})
		}
	default:
		return Result{}, ErrInvalidRequest
	}
	return result, nil
}

func resolveDirect(ctx context.Context, r *Request, deps Dependencies) (Result, error) {
	candidates, err := requestEndpoints(r, deps)
	if err != nil {
		return Result{}, err
	}
	request := externalDNS.NewMsg(r.Name, r.Type)
	if request == nil {
		return Result{}, ErrInvalidRequest
	}
	var errs []error
	for i, candidate := range candidates {
		if candidate.err != nil {
			errs = append(errs, candidate.err)
			continue
		}
		e := candidate.endpoint
		attempt, cancel := attemptContext(ctx, len(candidates)-i)
		response, used, err := exchange(attempt, request.Copy(), e, r, deps)
		cancel()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err = validateResponse(request, response); err != nil {
			errs = append(errs, err)
			continue
		}
		return makeResult(r, e.address, used, response), nil
	}
	return Result{}, fmt.Errorf("DNS query failed: %w", errors.Join(errs...))
}

type endpointCandidate struct {
	err      error
	endpoint Endpoint
}

func requestEndpoints(r *Request, deps Dependencies) ([]endpointCandidate, error) {
	if r.Endpoint != nil {
		return []endpointCandidate{{endpoint: *r.Endpoint}}, nil
	}
	if deps.ConfiguredServers == nil {
		return nil, ErrResolverUnavailable
	}
	servers, err := deps.ConfiguredServers()
	if err != nil {
		return nil, fmt.Errorf("read configured DNS servers: %w", err)
	}
	if len(servers) == 0 {
		return nil, ErrNoConfiguredServer
	}
	candidates := make([]endpointCandidate, 0, len(servers))
	for _, server := range servers {
		endpoint, parseErr := ParseEndpoint(server, r.ConfiguredPort)
		if parseErr == nil && endpoint.Transport != TransportUDP {
			parseErr = fmt.Errorf("%w: configured DNS servers require UDP", ErrInvalidEndpoint)
		}
		candidates = append(candidates, endpointCandidate{endpoint: endpoint, err: parseErr})
	}
	return candidates, nil
}

func attemptContext(parent context.Context, n int) (context.Context, context.CancelFunc) {
	d, ok := parent.Deadline()
	if !ok {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, time.Until(d)/time.Duration(n))
}

func exchange(ctx context.Context, q *externalDNS.Msg, e Endpoint, r *Request, deps Dependencies) (*externalDNS.Msg, Transport, error) {
	switch e.Transport {
	case TransportTLS:
		m, err := exchangeTLS(ctx, q, e, r.TLSConfig)
		return m, e.Transport, err
	case TransportHTTPS:
		m, err := exchangeHTTPS(ctx, q, e, r.TLSConfig)
		return m, e.Transport, err
	case TransportUDP, TransportTCP:
		if deps.PlaintextExchange == nil {
			return nil, e.Transport, ErrResolverUnavailable
		}
		m, err := deps.PlaintextExchange(ctx, q, e.Transport, e.address)
		if err == nil && e.Transport == TransportUDP && m != nil && m.Truncated {
			if validationErr := validateResponse(q, m); validationErr != nil {
				return nil, e.Transport, validationErr
			}
			m, err = deps.PlaintextExchange(ctx, q, TransportTCP, e.address)
			return m, TransportTCP, err
		}
		return m, e.Transport, err
	default:
		return nil, e.Transport, ErrInvalidRequest
	}
}

func validateResponse(q, r *externalDNS.Msg) error {
	if r == nil || !r.Response || r.ID != q.ID || r.Opcode != q.Opcode || len(q.Question) != 1 || len(r.Question) != 1 {
		return ErrResponseMismatch
	}
	a, b := q.Question[0], r.Question[0]
	if !strings.EqualFold(a.Header().Name, b.Header().Name) || externalDNS.RRToType(a) != externalDNS.RRToType(b) || a.Header().Class != b.Header().Class {
		return ErrResponseMismatch
	}
	return nil
}

func makeResult(q *Request, server string, t Transport, r *externalDNS.Msg) Result {
	status := externalDNS.RcodeToString[r.Rcode]
	if status == "" {
		status = strconv.Itoa(int(r.Rcode))
	}
	result := Result{
		Resolver: ResolverDirect, Server: &server, Transport: &t,
		QueryName: dnsutil.Fqdn(q.Name), QueryType: externalDNS.TypeToString[q.Type],
		Status: &status, ID: &r.ID, Authoritative: &r.Authoritative,
		Truncated: &r.Truncated, RecursionAvailable: &r.RecursionAvailable,
		Answers: make([]Answer, 0, len(r.Answer)),
	}
	for _, rr := range r.Answer {
		ttl := rr.Header().TTL
		typ := externalDNS.TypeToString[externalDNS.RRToType(rr)]
		if typ == "" {
			typ = "TYPE" + strconv.Itoa(int(externalDNS.RRToType(rr)))
		}
		class := externalDNS.ClassToString[rr.Header().Class]
		if class == "" {
			class = strconv.FormatUint(uint64(rr.Header().Class), 10)
		}
		value := ""
		if d := rr.Data(); d != nil {
			value = d.String()
		}
		result.Answers = append(result.Answers, Answer{Name: rr.Header().Name, Type: typ, Class: class, TTL: &ttl, Value: value})
	}
	return result
}

func tlsConfig(e Endpoint, in *tls.Config) (*tls.Config, error) {
	c := in.Clone()
	if c.ServerName == "" {
		host, _, err := net.SplitHostPort(e.address)
		if err != nil {
			return nil, fmt.Errorf("split DNS endpoint: %w", err)
		}
		c.ServerName = host
	}
	return c, nil
}

func exchangeTLS(ctx context.Context, q *externalDNS.Msg, e Endpoint, c *tls.Config) (_ *externalDNS.Msg, retErr error) {
	config, err := tlsConfig(e, c)
	if err != nil {
		return nil, err
	}
	conn, err := netconn.DialTLS(ctx, e.address, config)
	if err != nil {
		return nil, err
	}
	defer func() { retErr = errors.Join(retErr, conn.Close()) }()
	stopWatching, err := watchDNSConnectionContext(ctx, conn)
	if err != nil {
		return nil, err
	}
	defer stopWatching()
	if err := q.Pack(); err != nil {
		return nil, fmt.Errorf("pack DNS-over-TLS query: %w", err)
	}
	if len(q.Data) > externalDNS.MaxMsgSize {
		return nil, ErrInvalidRequest
	}
	frame := make([]byte, 2+len(q.Data))
	binary.BigEndian.PutUint16(frame, uint16(len(q.Data))) //nolint:gosec // Length is bounded by DNS MaxMsgSize.
	copy(frame[2:], q.Data)
	if _, err = conn.Write(frame); err != nil {
		return nil, contextError(ctx, err)
	}
	var l [2]byte
	if _, err = io.ReadFull(conn, l[:]); err != nil {
		return nil, contextError(ctx, err)
	}
	wire := make([]byte, int(binary.BigEndian.Uint16(l[:])))
	if _, err = io.ReadFull(conn, wire); err != nil {
		return nil, contextError(ctx, err)
	}
	m := &externalDNS.Msg{Data: wire}
	if err := m.Unpack(); err != nil {
		return nil, fmt.Errorf("unpack DNS-over-TLS response: %w", err)
	}
	return m, nil
}

func watchDNSConnectionContext(ctx context.Context, conn net.Conn) (func(), error) {
	// Install the configured deadline first so it cannot overwrite a cancellation deadline.
	if d, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(d); err != nil {
			return nil, fmt.Errorf("set DNS-over-TLS deadline: %w", err)
		}
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now()) //nolint:errcheck // Cancellation best-effort unblocks pending I/O.
		case <-done:
		}
	}()
	return func() { close(done) }, nil
}

func contextError(ctx context.Context, err error) error {
	if e := ctx.Err(); e != nil {
		return errors.Join(e, err)
	}
	var ne net.Error
	if d, ok := ctx.Deadline(); ok && !time.Now().Before(d) && errors.As(err, &ne) && ne.Timeout() {
		return errors.Join(context.DeadlineExceeded, err)
	}
	return err
}

func exchangeHTTPS(ctx context.Context, q *externalDNS.Msg, e Endpoint, c *tls.Config) (_ *externalDNS.Msg, retErr error) {
	if err := q.Pack(); err != nil {
		return nil, fmt.Errorf("pack DNS-over-HTTPS query: %w", err)
	}
	u := *e.dohURL
	u.Host = e.address
	config, err := tlsConfig(e, c)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: config}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(q.Data))
	if err != nil {
		return nil, fmt.Errorf("create DNS-over-HTTPS request: %w", err)
	}
	req.Header.Set("Content-Type", dnsMessageMediaType)
	req.Header.Set("Accept", dnsMessageMediaType)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send DNS-over-HTTPS request: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, resp.Body.Close()) }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: %s", errDoHStatus, resp.Status)
	}
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mt != dnsMessageMediaType {
		return nil, errDoHContentType
	}
	wire, err := io.ReadAll(io.LimitReader(resp.Body, externalDNS.MaxMsgSize+1))
	if err != nil {
		return nil, fmt.Errorf("read DNS-over-HTTPS response: %w", err)
	}
	if len(wire) > externalDNS.MaxMsgSize {
		return nil, errDoHResponseTooLarge
	}
	m := &externalDNS.Msg{Data: wire}
	if err := m.Unpack(); err != nil {
		return nil, fmt.Errorf("unpack DNS-over-HTTPS response: %w", err)
	}
	return m, nil
}

func exchangePlaintext(ctx context.Context, q *externalDNS.Msg, t Transport, address string) (*externalDNS.Msg, error) {
	timeout := 100 * 365 * 24 * time.Hour
	if d, ok := ctx.Deadline(); ok {
		timeout = time.Until(d)
		if timeout <= 0 {
			return nil, context.DeadlineExceeded
		}
	}
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, string(t), address)
	if err != nil {
		return nil, fmt.Errorf("dial DNS server: %w", err)
	}
	return exchangePlaintextConn(ctx, q, conn, timeout)
}

func exchangePlaintextConn(ctx context.Context, q *externalDNS.Msg, conn net.Conn, timeout time.Duration) (*externalDNS.Msg, error) {
	// The DNS client installs its own deadlines, which could overwrite a
	// cancellation deadline. Closing this owned connection cannot be undone.
	closeConn := sync.OnceValue(conn.Close)
	stop := context.AfterFunc(ctx, func() {
		_ = closeConn() //nolint:errcheck // The close result is joined below.
	})
	client := externalDNS.NewClient()
	client.ReadTimeout = timeout
	client.WriteTimeout = timeout
	r, _, xerr := client.ExchangeWithConn(ctx, q, conn)
	stop()
	err := errors.Join(xerr, closeConn())
	if err != nil {
		if ce := ctx.Err(); ce != nil {
			return nil, errors.Join(ce, err)
		}
		return nil, err
	}
	return r, nil
}
