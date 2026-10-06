package http

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/internal/asym"
)

type httpRoundTripperFunc func(*http.Request) (*http.Response, error)

// RoundTrip implements http.RoundTripper for a function.
func (function httpRoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func executeHTTPRequest(cmd *cobra.Command, options *httpOptions, prepared *httpPreparedRequest) error {
	if prepared == nil || prepared.request == nil {
		return fmt.Errorf("%w: request was not prepared", ErrInvalidFlags)
	}

	transport := newHTTPTransport(options, prepared.tlsConfig, prepared.resolver)
	defer transport.CloseIdleConnections()

	request, cancel := httpRequestWithTimeout(prepared.request, options.requestTimeout)
	defer cancel()
	// An explicitly empty field opts out, while net/http otherwise treats it as absent.
	transport.DisableCompression = len(request.Header.Values("Accept-Encoding")) != 0
	stopBodyClose := closeHTTPBodyOnCancellation(request.Context(), prepared.body)
	roundTripper, trace := httpTracingTransport(transport, options.trace)

	checkRedirect, redirectError := httpRedirectChecker(options)
	client := &http.Client{
		Transport:     roundTripper,
		CheckRedirect: checkRedirect,
	}

	response, requestErr := client.Do(request)
	pendingErr := httpPendingError(options, response, errors.Join(redirectError(), requestErr))
	renderErr := writeHTTPResponse(cmd, options, request, response, pendingErr, trace)
	var responseCloseErr error
	if response != nil && response.Body != nil {
		responseCloseErr = response.Body.Close()
	}
	stopCloseErr := stopBodyClose()
	var requestCloseErr error
	if prepared.body != nil {
		requestCloseErr = prepared.body.Close()
	}
	return errors.Join(renderErr, responseCloseErr, stopCloseErr, requestCloseErr)
}

func closeHTTPBodyOnCancellation(ctx context.Context, body io.Closer) func() error {
	if body == nil {
		return func() error { return nil }
	}
	done := make(chan error, 1)
	stop := context.AfterFunc(ctx, func() {
		done <- body.Close()
	})
	return func() error {
		if !stop() {
			return <-done
		}
		return nil
	}
}

func newHTTPTransport(options *httpOptions, configuredTLS *tls.Config, resolver httpResolver) *http.Transport {
	tlsConfig := configuredTLS
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	dialer := &net.Dialer{Timeout: options.timeout}
	return &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         resolver.dialContext(dialer, options.timeout),
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: options.timeout,
	}
}

func httpRequestWithTimeout(request *http.Request, timeout time.Duration) (*http.Request, context.CancelFunc) {
	if timeout <= 0 {
		return request, func() {}
	}
	requestContext, cancel := context.WithTimeout(request.Context(), timeout)
	return request.WithContext(requestContext), cancel
}

func httpTracingTransport(transport http.RoundTripper, enabled bool) (http.RoundTripper, *httpTrace) {
	if !enabled {
		return transport, nil
	}
	trace := newHTTPTrace()
	return httpRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return trace.roundTrip(request, transport)
	}), trace
}

func httpRedirectChecker(options *httpOptions) (func(*http.Request, []*http.Request) error, func() error) {
	var redirectErr error
	checker := func(_ *http.Request, via []*http.Request) error {
		if !options.follow {
			return http.ErrUseLastResponse
		}
		if len(via) > options.maxRedirects {
			redirectErr = fmt.Errorf("%w: maximum of %d redirects exceeded", errHTTPRedirect, options.maxRedirects)
			return http.ErrUseLastResponse
		}
		return nil
	}
	return checker, func() error { return redirectErr }
}

func httpPendingError(options *httpOptions, response *http.Response, pendingErr error) error {
	if pendingErr == nil && options.follow && responseHasUnfollowedBodyRedirect(response) {
		pendingErr = fmt.Errorf(
			"%w: %s response requires replaying a non-replayable request body",
			errHTTPRedirect,
			asym.EscapeDiagnosticValue(response.Status),
		)
	}
	if response != nil && options.fail && response.StatusCode >= http.StatusBadRequest && response.StatusCode <= 599 {
		pendingErr = errors.Join(pendingErr, fmt.Errorf("%w: %s", errHTTPStatus, asym.EscapeDiagnosticValue(response.Status)))
	}
	return pendingErr
}

func responseHasUnfollowedBodyRedirect(response *http.Response) bool {
	if response == nil || response.Request == nil || response.Header.Get("Location") == "" {
		return false
	}
	if response.StatusCode != http.StatusTemporaryRedirect && response.StatusCode != http.StatusPermanentRedirect {
		return false
	}
	request := response.Request
	return request.Body != nil && request.Body != http.NoBody && request.GetBody == nil
}
