package cmd

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestExampleHTTPResolve(t *testing.T) {
	t.Parallel()

	receivedHost := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		receivedHost <- request.Host
		writeHTTPTestString(t, writer, "resolved")
	}))
	t.Cleanup(server.Close)

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port := serverURL.Port()
	requestHost := net.JoinHostPort("127.0.0.2", port)
	resolve := requestHost + ":" + serverURL.Hostname()

	stdout, stderr, err := executeRootStreams(
		t,
		"http", "http://"+requestHost,
		"--resolve", resolve,
	)
	if err != nil {
		t.Fatalf("npc http --resolve: %v", err)
	}
	if stdout != "resolved" {
		t.Fatalf("stdout = %q, want resolved", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want no diagnostics", stderr)
	}
	if host := <-receivedHost; host != requestHost {
		t.Fatalf("Host = %q, want original URL host %q", host, requestHost)
	}
}
