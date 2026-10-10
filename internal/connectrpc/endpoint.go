// Package connectrpc invokes Connect RPCs without requiring generated clients.
package connectrpc

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ErrEndpoint identifies an invalid Connect procedure URL.
var ErrEndpoint = errors.New("invalid Connect endpoint")

var procedurePattern = regexp.MustCompile(`^/[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*/[A-Za-z_][A-Za-z0-9_]*$`)

// Endpoint retains the exact routing path separately from the protobuf procedure.
type Endpoint struct {
	URL       *url.URL
	Procedure string
}

// ParseEndpoint accepts a full procedure URL or a base URL and SERVICE/METHOD.
func ParseEndpoint(address, method string) (Endpoint, error) {
	parsed, err := parseAddress(address)
	if err != nil {
		return Endpoint{}, err
	}
	path := parsed.EscapedPath()
	if method != "" {
		parts := strings.Split(path, "/")
		if len(parts) >= 3 && procedurePattern.MatchString("/"+strings.Join(parts[len(parts)-2:], "/")) {
			return Endpoint{}, fmt.Errorf("%w: URL already names a method; use a trailing slash for a routed base URL", ErrEndpoint)
		}
		method = "/" + strings.TrimPrefix(method, "/")
		if !procedurePattern.MatchString(method) {
			return Endpoint{}, fmt.Errorf("%w: expected SERVICE/METHOD", ErrEndpoint)
		}
		path = strings.TrimRight(path, "/") + method
	}
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		return Endpoint{}, fmt.Errorf("%w: include SERVICE/METHOD in the URL or as a second argument", ErrEndpoint)
	}
	procedure := "/" + strings.Join(parts[len(parts)-2:], "/")
	if !procedurePattern.MatchString(procedure) {
		return Endpoint{}, fmt.Errorf("%w: expected a literal SERVICE/METHOD at the end of the URL", ErrEndpoint)
	}
	parsed.Path, err = url.PathUnescape(path)
	if err != nil {
		return Endpoint{}, fmt.Errorf("%w: %w", ErrEndpoint, err)
	}
	parsed.RawPath = path
	return Endpoint{URL: parsed, Procedure: procedure}, nil
}

// ParseBase accepts a discovery endpoint with an optional routing prefix.
func ParseBase(address string) (*url.URL, error) { return parseAddress(address) }

// BaseURL removes the literal procedure while retaining escaped routing prefixes.
func (endpoint Endpoint) BaseURL() *url.URL {
	base := *endpoint.URL
	escaped := strings.TrimSuffix(base.EscapedPath(), endpoint.Procedure)
	base.Path = strings.TrimSuffix(base.Path, endpoint.Procedure)
	base.RawPath = escaped
	return &base
}

func parseAddress(address string) (*url.URL, error) {
	if !strings.Contains(address, "://") {
		address = "https://" + address
	}
	parsed, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEndpoint, err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {

		return nil, fmt.Errorf("%w: use an HTTP(S) URL without user info, query, or fragment", ErrEndpoint)
	}
	return parsed, nil
}
