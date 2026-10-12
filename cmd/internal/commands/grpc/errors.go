// Package grpc constructs gRPC reflection and request commands.
package grpc

import "errors"

var (
	// ErrInvalidOptions identifies invalid gRPC command options.
	ErrInvalidOptions = errors.New("invalid gRPC options")
	// ErrInvalidMetadata identifies invalid gRPC request metadata.
	ErrInvalidMetadata = errors.New("invalid gRPC metadata")
	// ErrMessageLimit identifies a gRPC request that exceeds its size limit.
	ErrMessageLimit    = errors.New("gRPC message limit exceeded")
	errUnsupportedGRPC = errors.New("unsupported gRPC operation")
)
