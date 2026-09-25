package http_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExampleHTTPDataShortAlias(t *testing.T) {
	t.Parallel()

	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		if request.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", request.Method)
		}
		received <- string(body)
		if _, err := io.WriteString(writer, "accepted\n"); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	stdout, stderr, err := executeRootStreams(t, "http", server.URL, "-X", "POST", "-d", "hello")
	require.NoError(t, err, "npc http URL -X POST -d DATA: %v", err)
	if body := <-received; body != "hello" {
		t.Fatalf("body = %q, want literal data", body)
	}
	if stdout != "accepted\n" || stderr != "" {
		t.Fatalf("stdout, stderr = %q, %q", stdout, stderr)
	}
}
