package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

var errHTTPRenderTest = errors.New("HTTP render test failure")

func TestWriteHTTPJSONResponseStreamsBase64Body(t *testing.T) {
	t.Parallel()
	request := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "https", User: url.UserPassword("developer", "synthetic-password"), Host: "example.test", Path: "/start"},
	}
	response := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/2.0",
		Header:     http.Header{"Content-Type": {"application/octet-stream"}},
		Body:       io.NopCloser(strings.NewReader("\x00body\xff")),
		Request:    request,
	}
	command := &cobra.Command{}
	var output bytes.Buffer
	command.SetOut(&output)

	if err := writeHTTPResponse(command, &httpOptions{format: "json"}, request, response, nil, nil); err != nil {
		t.Fatal(err)
	}
	var envelope struct { //nolint:govet // Field order mirrors the JSON fields asserted by this test.
		Method       string `json:"method"`
		StatusCode   int    `json:"status_code"`
		Body         string `json:"body"`
		BodyEncoding string `json:"body_encoding"`
		Complete     bool   `json:"complete"`
	}
	if err := json.Unmarshal(output.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response envelope %q: %v", output.String(), err)
	}
	if strings.Contains(output.String(), "synthetic-password") {
		t.Fatalf("response envelope exposed URL password: %s", output.String())
	}
	body, err := base64.StdEncoding.DecodeString(envelope.Body)
	if err != nil {
		t.Fatal(err)
	}
	invalidEnvelope := envelope.Method != http.MethodGet || envelope.StatusCode != http.StatusOK ||
		string(body) != "\x00body\xff" || envelope.BodyEncoding != "base64" || !envelope.Complete
	if invalidEnvelope {
		t.Fatalf("envelope = %+v, decoded body = %q", envelope, body)
	}
}

func TestWriteHTTPJSONResponseClosesEnvelopeAfterBodyReadFailure(t *testing.T) {
	t.Parallel()
	readErr := fmt.Errorf("response read: %w", errHTTPRenderTest)
	request := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: "example.test"}}
	response := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header:     http.Header{},
		Body:       io.NopCloser(&httpFailingReader{data: []byte("partial"), err: readErr}),
		Request:    request,
	}
	command := &cobra.Command{}
	var output bytes.Buffer
	command.SetOut(&output)

	err := writeHTTPResponse(command, &httpOptions{format: "json"}, request, response, nil, nil)
	if !errors.Is(err, readErr) {
		t.Fatalf("error = %v, want body read failure", err)
	}
	var envelope struct { //nolint:govet // Field order mirrors the JSON fields asserted by this test.
		Body     string `json:"body"`
		Complete bool   `json:"complete"`
		Error    string `json:"error"`
	}
	if decodeErr := json.Unmarshal(output.Bytes(), &envelope); decodeErr != nil {
		t.Fatalf("decode response envelope %q: %v", output.String(), decodeErr)
	}
	if envelope.Complete || !strings.Contains(envelope.Error, readErr.Error()) {
		t.Fatalf("envelope = %+v, want incomplete response error", envelope)
	}
}

func TestWriteHTTPJSONResponseReportsConnectionFailure(t *testing.T) {
	t.Parallel()
	requestErr := fmt.Errorf("request failed: %w", errHTTPRenderTest)
	request := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "http", Host: "example.test"}}
	command := &cobra.Command{}
	var output bytes.Buffer
	command.SetOut(&output)

	err := writeHTTPResponse(command, &httpOptions{format: "json"}, request, nil, requestErr, nil)
	if !errors.Is(err, requestErr) {
		t.Fatalf("error = %v, want request failure", err)
	}
	var envelope struct { //nolint:govet // Field order mirrors the JSON fields asserted by this test.
		Body     string `json:"body"`
		Complete bool   `json:"complete"`
		Error    string `json:"error"`
	}
	if decodeErr := json.Unmarshal(output.Bytes(), &envelope); decodeErr != nil {
		t.Fatalf("decode response envelope %q: %v", output.String(), decodeErr)
	}
	if envelope.Body != "" || envelope.Complete || !strings.Contains(envelope.Error, requestErr.Error()) {
		t.Fatalf("envelope = %+v, want empty incomplete error response", envelope)
	}
}

func TestHTTPTracePairsSelectedConnectAttemptAndCertificateVerification(t *testing.T) {
	t.Parallel()
	verifiedDER := newTLSCertificateChain(t).Certificate[0]
	unrelatedDER := newTLSCertificateChain(t).Certificate[0]
	verifiedCertificate, err := x509.ParseCertificate(verifiedDER)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedCertificate, err := x509.ParseCertificate(unrelatedDER)
	if err != nil {
		t.Fatal(err)
	}

	trace := newHTTPTrace()
	request := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: "example.test"}}
	transport := httpRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		callbacks := httptrace.ContextClientTrace(request.Context())
		callbacks.ConnectStart("tcp6", "[2001:db8::1]:443")
		time.Sleep(time.Millisecond)
		callbacks.ConnectStart("tcp4", "192.0.2.10:443")
		time.Sleep(time.Millisecond)
		callbacks.ConnectDone("tcp4", "192.0.2.10:443", nil)
		callbacks.GotConn(httptrace.GotConnInfo{Conn: httpTraceTestConn{remote: httpTraceTestAddr("192.0.2.10:443")}})
		time.Sleep(time.Millisecond)
		callbacks.ConnectDone("tcp6", "[2001:db8::1]:443", errHTTPRenderTest)
		callbacks.TLSHandshakeStart()
		callbacks.TLSHandshakeDone(tls.ConnectionState{
			Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256,
			PeerCertificates: []*x509.Certificate{verifiedCertificate, unrelatedCertificate},
			VerifiedChains:   [][]*x509.Certificate{{verifiedCertificate}},
		}, nil)
		return &http.Response{
			StatusCode: http.StatusOK, Status: "200 OK", Proto: "HTTP/1.1",
			Header: http.Header{}, Body: http.NoBody, Request: request,
		}, nil
	})
	response, err := trace.roundTrip(request, transport)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	})
	trace.finish()
	views := trace.views()
	if len(views) != 1 || views[0].Address != "192.0.2.10:443" || views[0].Network != "tcp4" || views[0].Connect == "" {
		t.Fatalf("trace views = %+v, want selected tcp4 attempt", views)
	}
	if len(views[0].Attempts) != 2 || views[0].Attempts[0].Selected || !views[0].Attempts[1].Selected {
		t.Fatalf("connect attempts = %+v, want only tcp4 selected", views[0].Attempts)
	}
	if views[0].TLS == nil || !views[0].TLS.Verified || len(views[0].TLS.Certificates) != 2 {
		t.Fatalf("TLS trace = %+v, want verified handshake with two peer certificates", views[0].TLS)
	}
	for i, wantVerified := range []bool{true, false} {
		var certificate struct {
			Verified bool `json:"verified"`
		}
		if err := json.Unmarshal(views[0].TLS.Certificates[i], &certificate); err != nil {
			t.Fatal(err)
		}
		if certificate.Verified != wantVerified {
			t.Fatalf("certificate %d verified = %t, want %t", i, certificate.Verified, wantVerified)
		}
	}
}

type httpFailingReader struct {
	err  error
	data []byte
}

type httpTraceTestAddr string

func (address httpTraceTestAddr) Network() string { return "tcp" }
func (address httpTraceTestAddr) String() string  { return string(address) }

type httpTraceTestConn struct{ remote net.Addr }

func (connection httpTraceTestConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (connection httpTraceTestConn) Write(buffer []byte) (int, error) { return len(buffer), nil }
func (connection httpTraceTestConn) Close() error                     { return nil }
func (connection httpTraceTestConn) LocalAddr() net.Addr              { return httpTraceTestAddr("127.0.0.1:1234") }
func (connection httpTraceTestConn) RemoteAddr() net.Addr             { return connection.remote }
func (connection httpTraceTestConn) SetDeadline(time.Time) error      { return nil }
func (connection httpTraceTestConn) SetReadDeadline(time.Time) error  { return nil }
func (connection httpTraceTestConn) SetWriteDeadline(time.Time) error { return nil }

func (reader *httpFailingReader) Read(buffer []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, reader.err
	}
	n := copy(buffer, reader.data)
	reader.data = reader.data[n:]
	return n, nil
}
