package connectrpc

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"

	"connectrpc.com/connect/v2"
)

// JSONCodec preserves protobuf JSON and numeric lexemes without a descriptor.
// Connect owns wire framing; MaxBytes independently bounds uncompressed JSON.
type JSONCodec struct{ MaxBytes int }

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
func (codec JSONCodec) UnmarshalRead(_ context.Context, input io.Reader, message any) error {
	reader := input
	var limited *io.LimitedReader
	if codec.MaxBytes > 0 {
		limited = &io.LimitedReader{R: input, N: int64(codec.MaxBytes)}
		reader = limited
	}
	decodeErr := json.UnmarshalRead(reader, message)
	if limited != nil && limited.N == 0 {
		var extra [1]byte
		if n, err := io.ReadFull(input, extra[:]); n > 0 {
			return connect.NewError(connect.CodeResourceExhausted, "uncompressed JSON exceeds message limit").WithCause(ErrMessageSize)
		} else if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("finish Connect JSON: %w", err)
		}
	}
	if decodeErr != nil {
		return fmt.Errorf("decode Connect JSON: %w", decodeErr)
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
