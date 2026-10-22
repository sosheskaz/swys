package connectrpc_test

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	"github.com/sosheskaz/swys/internal/connectrpc"
)

const maxFuzzConnectJSONSize = 1 << 10

var errFuzzConnectJSONSource = errors.New("fuzz Connect JSON source failure")

// FuzzJSONCodecUnmarshalReadLimits exercises the codec that decodes every crpc
// Connect JSON response body, at generated size limits spanning the exact
// boundary: a body that fits must decode identically to an unlimited decode,
// while a body with any bytes left beyond the limit must be rejected as
// oversized rather than partially accepted — including bodies whose extra
// bytes are only trailing whitespace.
func FuzzJSONCodecUnmarshalReadLimits(f *testing.F) {
	f.Add([]byte{}, uint16(0), uint8(1))
	f.Add([]byte(`{"count":9007199254740993}`), uint16(26), uint8(3))
	f.Add([]byte(`{"count":9007199254740993}`), uint16(27), uint8(255))
	f.Add([]byte(`{"count":1} `), uint16(10), uint8(1))
	f.Add([]byte(`  null  `), uint16(8), uint8(7))
	f.Add([]byte(`"ok" `), uint16(3), uint8(1))
	f.Add([]byte(`{"truncated":`), uint16(13), uint8(5))
	f.Add([]byte(`"message"x`), uint16(9), uint8(2))
	f.Add([]byte(`{"a":1,"a":2}`), uint16(100), uint8(64))
	f.Add([]byte("\xff\xfe invalid"), uint16(64), uint8(9))

	f.Fuzz(func(t *testing.T, body []byte, fuzzLimit uint16, sourceChunk uint8) {
		if len(body) > maxFuzzConnectJSONSize {
			t.Skip()
		}
		limit := int(fuzzLimit)%(len(body)+2) + 1

		var limited jsontext.Value
		limitedErr := (connectrpc.JSONCodec{MaxBytes: limit}).UnmarshalRead(
			t.Context(),
			newFuzzConnectJSONReader(body, sourceChunk),
			&limited,
		)
		var unlimited jsontext.Value
		unlimitedErr := (connectrpc.JSONCodec{}).UnmarshalRead(
			t.Context(),
			newFuzzConnectJSONReader(body, sourceChunk),
			&unlimited,
		)

		if limit >= len(body) {
			if errors.Is(limitedErr, connectrpc.ErrMessageSize) {
				t.Fatalf("body of %d bytes at limit %d rejected as oversized", len(body), limit)
			}
			fuzzCheckSameConnectJSONDecode(t, limitedErr, unlimitedErr, limited, unlimited)
			return
		}
		// The body exceeds the limit. The codec must report the size failure,
		// or decoding must have failed on its own before the limit mattered —
		// matching the unlimited decode exactly. Partial acceptance of an
		// over-limit body is never allowed.
		if !errors.Is(limitedErr, connectrpc.ErrMessageSize) {
			if limitedErr == nil {
				t.Fatalf("over-limit body accepted: %d bytes at limit %d", len(body), limit)
			}
			fuzzCheckSameConnectJSONDecode(t, limitedErr, unlimitedErr, limited, unlimited)
		}
	})
}

// FuzzJSONCodecUnmarshalReadSourceFailures adds a failing source after the
// generated body, the way a connection reset can end a response stream. The
// limited decode may only succeed when the whole body fits strictly inside
// the limit; otherwise the failure must surface as either the size error, the
// source's own error, or the same decode failure an unlimited decode sees.
func FuzzJSONCodecUnmarshalReadSourceFailures(f *testing.F) {
	f.Add([]byte{}, uint16(0), uint8(1))
	f.Add([]byte(`{"count":2}`), uint16(11), uint8(3))
	f.Add([]byte(`{"count":2}`), uint16(12), uint8(255))
	f.Add([]byte(`{"count":2}`), uint16(13), uint8(1))
	f.Add([]byte(`{"cut":"short"`), uint16(6), uint8(2))
	f.Add([]byte(`"ok" trailing`), uint16(3), uint8(7))

	f.Fuzz(func(t *testing.T, body []byte, fuzzLimit uint16, sourceChunk uint8) {
		if len(body) > maxFuzzConnectJSONSize {
			t.Skip()
		}
		limit := int(fuzzLimit)%(len(body)+2) + 1

		var limited jsontext.Value
		limitedErr := (connectrpc.JSONCodec{MaxBytes: limit}).UnmarshalRead(
			t.Context(),
			fuzzConnectJSONFailingSource(body, sourceChunk),
			&limited,
		)
		var unlimited jsontext.Value
		unlimitedErr := (connectrpc.JSONCodec{}).UnmarshalRead(
			t.Context(),
			fuzzConnectJSONFailingSource(body, sourceChunk),
			&unlimited,
		)

		wantSuccess := unlimitedErr == nil && len(body) < limit
		if (limitedErr == nil) != wantSuccess {
			t.Fatalf("limited decode error = %v with unlimited error %v and body %d at limit %d",
				limitedErr, unlimitedErr, len(body), limit)
		}
		if limitedErr == nil {
			if string(limited) != string(unlimited) {
				t.Fatalf("decoded value = %q, want %q", string(limited), string(unlimited))
			}
			return
		}
		if errors.Is(limitedErr, connectrpc.ErrMessageSize) {
			if len(body) <= limit {
				t.Fatalf("body of %d bytes at limit %d rejected as oversized", len(body), limit)
			}
			return
		}
		if errors.Is(limitedErr, errFuzzConnectJSONSource) {
			return
		}
		if unlimitedErr == nil || limitedErr.Error() != unlimitedErr.Error() {
			t.Fatalf("limited decode error = %v, want unlimited decode error %v", limitedErr, unlimitedErr)
		}
	})
}

func fuzzCheckSameConnectJSONDecode(t *testing.T, limitedErr, unlimitedErr error, limited, unlimited jsontext.Value) {
	t.Helper()
	if (limitedErr == nil) != (unlimitedErr == nil) {
		t.Fatalf("limited decode error = %v, want unlimited decode outcome %v", limitedErr, unlimitedErr)
	}
	if limitedErr != nil {
		if limitedErr.Error() != unlimitedErr.Error() {
			t.Fatalf("limited decode error = %v, want unlimited decode error %v", limitedErr, unlimitedErr)
		}
		return
	}
	if string(limited) != string(unlimited) {
		t.Fatalf("decoded value = %q, want %q", string(limited), string(unlimited))
	}
}

func fuzzConnectJSONFailingSource(body []byte, chunk uint8) io.Reader {
	return io.MultiReader(newFuzzConnectJSONReader(body, chunk), iotest.ErrReader(errFuzzConnectJSONSource))
}

// newFuzzConnectJSONReader fragments the body at a generated chunk size so
// the limit probe and decoder see arbitrary read boundaries.
func newFuzzConnectJSONReader(body []byte, chunk uint8) io.Reader {
	return &fuzzConnectJSONChunkReader{source: bytes.NewReader(body), maximum: int(chunk%64) + 1}
}

type fuzzConnectJSONChunkReader struct {
	source  *bytes.Reader
	maximum int
}

func (reader *fuzzConnectJSONChunkReader) Read(buffer []byte) (int, error) {
	if len(buffer) > reader.maximum {
		buffer = buffer[:reader.maximum]
	}
	read, err := reader.source.Read(buffer)
	return read, err //nolint:wrapcheck // preserve io.Reader error identity in the fuzz fixture
}
