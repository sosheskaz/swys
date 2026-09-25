package dns

import "errors"

var (
	// ErrInvalidDNSOptions identifies invalid DNS command options.
	ErrInvalidDNSOptions     = errors.New("invalid DNS options")
	errUnsupportedSystemType = errors.New("record type is unavailable from the system resolver")
)
