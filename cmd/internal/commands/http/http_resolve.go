package http

import (
	"fmt"

	"github.com/sosheskaz/swys/internal/httptransport"
)

type httpResolver = httptransport.Resolver

func parseHTTPResolves(values []string) (httpResolver, error) {
	resolver, err := httptransport.ParseResolves(values)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFlags, err)
	}
	return resolver, nil
}
