// Package http constructs HTTP request commands.
package http

import "errors"

var (
	// ErrInvalidFlags identifies invalid HTTP command options.
	ErrInvalidFlags       = errors.New("invalid HTTP options")
	errInvalidHTTPResolve = errors.New("invalid HTTP resolve rule")
	errHTTPStatus         = errors.New("HTTP response status indicates failure")
	errHTTPRedirect       = errors.New("HTTP redirect could not be followed")
)
