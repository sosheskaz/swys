package cmd

import (
	"net/http"
	"testing"
)

func TestExampleDNSOverTLS(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	endpoint, requests := startDoTTestServer(t, identity, false, standardDNSReply)

	stdout, stderr, err := executeRootStreams(
		t,
		"dns", endpoint, "example.test", "A",
		"--ca", identity.caCertPath,
		"--short",
	)
	if err != nil {
		t.Fatalf("npc dns @tls://server name A: %v", err)
	}
	if stdout != "192.0.2.44\n" || stderr != "" {
		t.Fatalf("stdout = %q, stderr = %q", stdout, stderr)
	}
	if got := <-requests; got.err != nil || got.request == nil || got.request.Question[0].Header().Name != "example.test." {
		t.Fatalf("DoT request = %+v", got)
	}
}

func TestExampleDNSOverHTTPS(t *testing.T) {
	t.Parallel()

	identity := newEncryptedDNSTestIdentity(t, []string{"localhost"}, nil)
	requests := make(chan dohTestRequest, 1)
	server := startDoHTestServer(t, identity, false, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		message, err := readDoHTestRequest(request)
		requests <- dohTestRequest{method: request.Method, contentType: request.Header.Get("Content-Type"), uri: request.URL.RequestURI(), message: message, err: err}
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writeDoHTestResponse(t, writer, standardDNSReply(message))
	}))

	stdout, stderr, err := executeRootStreams(
		t,
		"dns", server.endpoint("localhost", "/lookup?profile=example"), "example.test",
		"--ca", identity.caCertPath,
		"--short",
	)
	if err != nil {
		t.Fatalf("npc dns @https://server/lookup?profile=example name: %v", err)
	}
	if stdout != "192.0.2.44\n" || stderr != "" {
		t.Fatalf("stdout = %q, stderr = %q", stdout, stderr)
	}
	got := <-requests
	if got.err != nil || got.method != http.MethodPost || got.contentType != "application/dns-message" || got.uri != "/lookup?profile=example" {
		t.Fatalf("DoH request = %+v", got)
	}
}
