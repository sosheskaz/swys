package connectrpc_test

import (
	"bytes"
	"encoding/json/jsontext"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/internal/connectrpc"
)

func TestJSONCodecPreservesMessageValues(t *testing.T) {
	t.Parallel()
	for _, input := range []string{`{"count":9007199254740993}`, `"message"`, `null`, `[]`, `-1.234567890123456789e+99`} {
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			value, err := connectrpc.ParseJSON([]byte(input))
			require.NoError(t, err)
			var output bytes.Buffer
			codec := connectrpc.JSONCodec{}
			require.NoError(t, codec.MarshalWrite(t.Context(), &output, &value))
			assert.Equal(t, input, output.String())
			var received jsontext.Value
			require.NoError(t, codec.UnmarshalRead(t.Context(), &output, &received))
			assert.Equal(t, input, string(received))
		})
	}
	for _, input := range []string{"", "{} {}", `{"a":1,"a":2}`, "\"\xff\"", "{", "null garbage"} {
		t.Run("invalid "+input, func(t *testing.T) {
			t.Parallel()
			_, err := connectrpc.ParseJSON([]byte(input))
			require.Error(t, err)
			var received jsontext.Value
			require.Error(t, (connectrpc.JSONCodec{}).UnmarshalRead(t.Context(), strings.NewReader(input), &received))
		})
	}
}
