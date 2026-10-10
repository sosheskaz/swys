package connectrpc

import (
	"context"
	"crypto/tls"
	"encoding/json/jsontext"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/sosheskaz/swys/internal/httptransport"
)

// Options bounds individual messages and connection establishment independently.
type Options struct {
	TLS            *tls.Config
	Resolves       httptransport.Resolver
	ConnectTimeout time.Duration
	MaxMessageSize int
}

// Client owns the HTTP connection pool for one command invocation.
type Client struct {
	client    *connect.Client
	transport *http.Transport
	endpoint  Endpoint
}

// NewClient uses the Connect protocol over negotiated HTTPS or HTTP/1.1 cleartext.
func NewClient(endpoint Endpoint, options Options) *Client {
	dialer := &net.Dialer{Timeout: options.ConnectTimeout}
	transport := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		DialContext:            options.Resolves.DialContext(dialer, options.ConnectTimeout),
		TLSClientConfig:        options.TLS,
		TLSHandshakeTimeout:    options.ConnectTimeout,
		ForceAttemptHTTP2:      true,
		MaxResponseHeaderBytes: 1 << 20,
	}
	httpClient := &http.Client{
		Transport:     &requestTransport{base: transport, endpoint: endpoint, setup: options.ConnectTimeout},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	baseURL := endpoint.URL.Scheme + "://" + endpoint.URL.Host
	connectTransport := connecthttp.NewTransport(httpClient, baseURL,
		connecthttp.WithCodecs(JSONCodec{}),
		connecthttp.WithReadMaxBytes(options.MaxMessageSize),
		connecthttp.WithSendMaxBytes(options.MaxMessageSize),
	)
	return &Client{client: connect.NewClient(connectTransport), transport: transport, endpoint: endpoint}
}

// Close releases idle HTTP connections after the command completes.
func (client *Client) Close() { client.transport.CloseIdleConnections() }

// Unary invokes a procedure, preserving headers and transport details in ctx's CallInfo.
func (client *Client) Unary(ctx context.Context, request jsontext.Value) (jsontext.Value, error) {
	var response jsontext.Value
	if err := client.client.CallUnary(ctx, connect.Spec{Procedure: client.endpoint.Procedure}, &request, &response); err != nil {
		return nil, fmt.Errorf("invoke Connect method: %w", err)
	}
	return response, nil
}

type requestTransport struct {
	base     http.RoundTripper
	endpoint Endpoint
	setup    time.Duration
}

// RoundTrip bounds setup without imposing a deadline on an acquired connection.
func (transport *requestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancelCause(request.Context())
	var timer *time.Timer
	if transport.setup > 0 {
		timer = time.AfterFunc(transport.setup, func() {
			cancel(fmt.Errorf("connection setup timed out after %s: %w", transport.setup, context.DeadlineExceeded))
		})
		defer timer.Stop()
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			GotConn: func(httptrace.GotConnInfo) { timer.Stop() },
		})
	}
	request = request.Clone(ctx)
	// Connect-Go joins decoded paths. Retain escaped routing prefixes verbatim.
	urlCopy := *transport.endpoint.URL
	request.URL = &urlCopy
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		cause := context.Cause(ctx)
		cancel(nil)
		if cause != nil {
			return nil, fmt.Errorf("perform Connect HTTP request: %w", cause)
		}
		return nil, fmt.Errorf("perform Connect HTTP request: %w", err)
	}
	response.Body = &responseBody{ReadCloser: response.Body, cancel: cancel}
	return response, nil
}

type responseBody struct {
	io.ReadCloser
	cancel context.CancelCauseFunc
}

// Close releases both the response and its request context.
func (body *responseBody) Close() error {
	defer body.cancel(nil)
	if err := body.ReadCloser.Close(); err != nil {
		return fmt.Errorf("close Connect response: %w", err)
	}
	return nil
}
