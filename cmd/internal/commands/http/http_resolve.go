package http

import (
	"fmt"

	"github.com/sosheskaz/swys/internal/netconn"
)

type httpResolver = netconn.Resolver

func parseHTTPResolves(values []string) (httpResolver, error) {
	resolver, err := netconn.ParseResolves(values)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFlags, err)
	}
	return resolver, nil
}
