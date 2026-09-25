package http

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type httpResolveKey struct {
	host string
	port uint16
}

type httpResolver map[httpResolveKey][]netip.Addr

func parseHTTPResolves(values []string) (httpResolver, error) {
	resolver := make(httpResolver, len(values))
	for _, value := range values {
		key, addresses, err := parseHTTPResolve(value)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid --resolve %q: %w", ErrInvalidFlags, value, err)
		}
		resolver[key] = addresses
	}
	return resolver, nil
}

func parseHTTPResolve(value string) (httpResolveKey, []netip.Addr, error) {
	if strings.HasPrefix(value, "+") {
		return httpResolveKey{}, nil, fmt.Errorf("%w: temporary entries are not supported", errInvalidHTTPResolve)
	}
	if strings.HasPrefix(value, "-") {
		return httpResolveKey{}, nil, fmt.Errorf("%w: entry removal is not supported", errInvalidHTTPResolve)
	}

	host, remainder, err := splitHTTPResolveHost(value)
	if err != nil {
		return httpResolveKey{}, nil, err
	}
	portValue, addressValues, exists := strings.Cut(remainder, ":")
	if !exists || addressValues == "" {
		return httpResolveKey{}, nil, fmt.Errorf("%w: expected HOST:PORT:ADDRESS[,ADDRESS]", errInvalidHTTPResolve)
	}
	port, err := parseHTTPResolvePort(portValue)
	if err != nil {
		return httpResolveKey{}, nil, err
	}
	addresses, err := parseHTTPResolveAddresses(addressValues)
	if err != nil {
		return httpResolveKey{}, nil, err
	}
	return httpResolveKey{host: host, port: port}, addresses, nil
}

func splitHTTPResolveHost(value string) (string, string, error) {
	if value == "" {
		return "", "", fmt.Errorf("%w: expected HOST:PORT:ADDRESS[,ADDRESS]", errInvalidHTTPResolve)
	}
	if strings.HasPrefix(value, "[") {
		end := strings.Index(value, "]:")
		if end < 0 {
			return "", "", fmt.Errorf("%w: expected bracketed IPv6 host followed by a port", errInvalidHTTPResolve)
		}
		host, err := netip.ParseAddr(value[1:end])
		if err != nil || !host.Is6() {
			return "", "", fmt.Errorf("%w: host brackets require an IPv6 address", errInvalidHTTPResolve)
		}
		return strings.ToLower(host.String()), value[end+2:], nil
	}

	host, remainder, exists := strings.Cut(value, ":")
	if !exists || !validHTTPResolveHostname(host) {
		return "", "", fmt.Errorf("%w: host must be a non-empty hostname or IP address", errInvalidHTTPResolve)
	}
	if host == "*" {
		return "", "", fmt.Errorf("%w: wildcard hosts are not supported", errInvalidHTTPResolve)
	}
	if address, err := netip.ParseAddr(host); err == nil {
		host = address.String()
	}
	return strings.ToLower(host), remainder, nil
}

func validHTTPResolveHostname(host string) bool {
	if host == "" || strings.ContainsAny(host, "[]/?#@,") {
		return false
	}
	return !strings.ContainsFunc(host, func(char rune) bool {
		return char > unicode.MaxASCII || unicode.IsSpace(char) || unicode.IsControl(char)
	})
}

func parseHTTPResolvePort(value string) (uint16, error) {
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("%w: port must be an integer from 1 to 65535", errInvalidHTTPResolve)
	}
	return uint16(port), nil
}

func parseHTTPResolveAddresses(value string) ([]netip.Addr, error) {
	parts := strings.Split(value, ",")
	addresses := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		bracketed := strings.HasPrefix(part, "[") && strings.HasSuffix(part, "]")
		addressValue := part
		if bracketed {
			addressValue = part[1 : len(part)-1]
		}
		address, err := netip.ParseAddr(addressValue)
		if err != nil || address.Is6() != bracketed {
			return nil, fmt.Errorf("%w: address %q must be numeric IPv4 or bracketed IPv6", errInvalidHTTPResolve, part)
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func (resolver httpResolver) dialContext(
	dialer *net.Dialer,
	timeout time.Duration,
) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		addresses, port, exists := resolver.lookup(address)
		if !exists {
			return dialer.DialContext(ctx, network, address)
		}
		return dialHTTPResolvedAddresses(ctx, dialer, network, address, port, addresses, timeout)
	}
}

func (resolver httpResolver) lookup(address string) ([]netip.Addr, uint16, bool) {
	host, portValue, err := net.SplitHostPort(address)
	if err != nil {
		return nil, 0, false
	}
	port, err := parseHTTPResolvePort(portValue)
	if err != nil {
		return nil, 0, false
	}
	if parsed, err := netip.ParseAddr(host); err == nil {
		host = parsed.String()
	}
	addresses, exists := resolver[httpResolveKey{host: strings.ToLower(host), port: port}]
	return addresses, port, exists
}

func dialHTTPResolvedAddresses(
	ctx context.Context,
	dialer *net.Dialer,
	network string,
	originalAddress string,
	port uint16,
	addresses []netip.Addr,
	timeout time.Duration,
) (net.Conn, error) {
	dialContext := ctx
	cancel := func() {}
	if timeout > 0 {
		dialContext, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	attemptErrors := make([]error, 0, len(addresses))
	for index, address := range addresses {
		if err := dialContext.Err(); err != nil {
			attemptErrors = append(attemptErrors, err)
			break
		}
		attemptContext, stopAttempt := httpResolveAttemptContext(dialContext, len(addresses)-index)
		mappedAddress := net.JoinHostPort(address.String(), strconv.FormatUint(uint64(port), 10))
		connection, err := dialer.DialContext(attemptContext, network, mappedAddress)
		stopAttempt()
		if err == nil {
			return connection, nil
		}
		attemptErrors = append(attemptErrors, fmt.Errorf("dial %s: %w", mappedAddress, err))
	}
	return nil, fmt.Errorf("dial %s using --resolve: %w", originalAddress, errors.Join(attemptErrors...))
}

func httpResolveAttemptContext(ctx context.Context, attemptsRemaining int) (context.Context, context.CancelFunc) {
	deadline, exists := ctx.Deadline()
	if !exists || attemptsRemaining <= 1 {
		return context.WithCancel(ctx)
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, remaining/time.Duration(attemptsRemaining))
}
