package connectrpc

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
)

// JSONCodec preserves protobuf JSON and numeric lexemes without a descriptor.
// Connect owns wire framing and per-message size limits around this codec.
type JSONCodec struct{}

// Name identifies the Connect JSON serialization.
func (JSONCodec) Name() string { return "json" }

// MarshalWrite writes one validated JSON value.
func (JSONCodec) MarshalWrite(_ context.Context, output io.Writer, message any) error {
	if err := json.MarshalWrite(output, message); err != nil {
		return fmt.Errorf("encode Connect JSON: %w", err)
	}
	return nil
}

// UnmarshalRead rejects malformed JSON, duplicate names, and trailing values.
func (JSONCodec) UnmarshalRead(_ context.Context, input io.Reader, message any) error {
	if err := json.UnmarshalRead(input, message); err != nil {
		return fmt.Errorf("decode Connect JSON: %w", err)
	}
	return nil
}

// ParseJSON validates a single JSON message without converting numbers to floats.
func ParseJSON(data []byte) (jsontext.Value, error) {
	var value jsontext.Value
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("parse Connect JSON: %w", err)
	}
	return value, nil
}
