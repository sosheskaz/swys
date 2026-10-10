package connectrpc_test

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/sosheskaz/swys/internal/connectrpc"
)

func BenchmarkStreamJSONLines(b *testing.B) {
	const procedure = "/benchmark.Stream/Upload"
	service := connect.NewServer()
	service.Register(connect.Method{
		Spec: connect.Spec{Procedure: procedure, StreamType: connect.StreamTypeClient},
		Handler: func(_ context.Context, _ connect.Spec, stream connect.ServerStream) error {
			count := 0
			for {
				var value jsontext.Value
				if err := stream.Receive(&value); err != nil {
					if !errors.Is(err, io.EOF) {
						return fmt.Errorf("receive benchmark message: %w", err)
					}
					break
				}
				count++
			}
			response := jsontext.Value(strconv.Itoa(count))
			return stream.Send(&response)
		},
	})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, service, connecthttp.WithCodecs(connectrpc.JSONCodec{}))
	server := httptest.NewServer(mux)
	b.Cleanup(server.Close)
	endpoint, err := connectrpc.ParseEndpoint(server.URL+procedure, "")
	if err != nil {
		b.Fatal(err)
	}
	client := connectrpc.NewClient(endpoint, connectrpc.Options{MaxMessageSize: 8192})
	b.Cleanup(client.Close)
	line := `{"text":"` + strings.Repeat("x", 4096-len("{\"text\":\"\"}\n")) + "\"}\n"
	for _, size := range []int{4096, 1 << 20, 64 << 20} {
		b.Run(fmt.Sprintf("%dKiB", size/1024), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				input := connectrpc.NewJSONLines(io.LimitReader(&repeatingLine{line: line}, int64(size)), len(line))
				var response string
				err := client.Stream(b.Context(), connect.StreamTypeClient, func(context.Context) (jsontext.Value, error) {
					return input.Next()
				}, func(value jsontext.Value) error { response = string(value); return nil })
				if err != nil {
					b.Fatal(err)
				}
				if response != strconv.Itoa(size/len(line)) {
					b.Fatalf("received message count %q, want %d", response, size/len(line))
				}
			}
		})
	}
}

type repeatingLine struct {
	line     string
	position int
}

func (reader *repeatingLine) Read(buffer []byte) (int, error) {
	n := copy(buffer, reader.line[reader.position:])
	reader.position = (reader.position + n) % len(reader.line)
	return n, nil
}
