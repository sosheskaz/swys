package http

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/internal/textdisplay"
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

	require.NoError(t, writeHTTPResponse(command, &httpOptions{selection: "response", format: "json"}, request, response, nil, nil))
	var envelope struct { //nolint:govet // Field order mirrors the JSON fields asserted by this test.
		Method       string `json:"method"`
		StatusCode   int    `json:"status_code"`
		Body         string `json:"body"`
		BodyEncoding string `json:"body_encoding"`
		Complete     bool   `json:"complete"`
	}
	require.NoError(t, json.Unmarshal(output.Bytes(), &envelope), "decode response envelope %q", output.String())
	assert.NotContains(t, output.String(), "synthetic-password")
	body, err := base64.StdEncoding.DecodeString(envelope.Body)
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, envelope.Method)
	assert.Equal(t, http.StatusOK, envelope.StatusCode)
	assert.Equal(t, "\x00body\xff", string(body))
	assert.Equal(t, "base64", envelope.BodyEncoding)
	assert.True(t, envelope.Complete)
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

	err := writeHTTPResponse(command, &httpOptions{selection: "response", format: "json"}, request, response, nil, nil)
	require.ErrorIs(t, err, readErr)
	var envelope struct { //nolint:govet // Field order mirrors the JSON fields asserted by this test.
		Body     string `json:"body"`
		Complete bool   `json:"complete"`
		Error    string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(output.Bytes(), &envelope), "decode response envelope %q", output.String())
	assert.False(t, envelope.Complete)
	assert.Contains(t, envelope.Error, readErr.Error())
}

func TestWriteHTTPJSONResponseReportsConnectionFailure(t *testing.T) {
	t.Parallel()
	requestErr := fmt.Errorf("request failed: %w", errHTTPRenderTest)
	request := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "http", Host: "example.test"}}
	command := &cobra.Command{}
	var output bytes.Buffer
	command.SetOut(&output)

	err := writeHTTPResponse(command, &httpOptions{selection: "response", format: "json"}, request, nil, requestErr, nil)
	require.ErrorIs(t, err, requestErr)
	var envelope struct { //nolint:govet // Field order mirrors the JSON fields asserted by this test.
		Body     string `json:"body"`
		Complete bool   `json:"complete"`
		Error    string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(output.Bytes(), &envelope), "decode response envelope %q", output.String())
	assert.Empty(t, envelope.Body)
	assert.False(t, envelope.Complete)
	assert.Contains(t, envelope.Error, requestErr.Error())
}

func TestHTTPTraceTextOmitsUnavailableFieldsAndAlignsSections(t *testing.T) {
	t.Parallel()
	start := time.Unix(1, 0)
	for _, test := range []struct {
		name string
		hop  *httpTraceHop
		want string
	}{
		{
			name: "unavailable connection",
			hop:  &httpTraceHop{method: "GET", url: "http://example.test", start: start, end: start.Add(time.Second)},
			want: "http trace 1: GET http://example.test\n\n  Timing\n    total  1s\n",
		},
		{
			name: "aligned available fields",
			hop: &httpTraceHop{
				method: "GET", url: "https://example.test", start: start, end: start.Add(time.Second),
				network: "tcp", address: "192.0.2.1:443", reused: "new", firstByte: start.Add(time.Millisecond),
				connectAttempts: []*httpTraceConnectAttempt{{network: "tcp", address: "192.0.2.1:443", start: start, end: start.Add(time.Millisecond)}},
				tls:             &httpTraceTLS{version: "TLS 1.3", cipher: "TLS_AES_128_GCM_SHA256"},
			},
			want: `http trace 1: GET https://example.test

  Connection
    network     tcp
    address     192.0.2.1:443
    connection  new
    attempt     tcp 192.0.2.1:443, duration=1ms

  Timing
    connect     1ms
    first byte  1ms
    transfer    999ms
    total       1s

  TLS
    version   TLS 1.3
    cipher    TLS_AES_128_GCM_SHA256
    verified  false
`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			trace := &httpTrace{hops: []*httpTraceHop{test.hop}}
			require.NoError(t, trace.writeText(&output, textdisplay.Options{}))
			assert.Equal(t, test.want, output.String())
		})
	}
}

func TestHTTPTracePairsSelectedConnectAttemptAndCertificateVerification(t *testing.T) {
	t.Parallel()
	verifiedDER := newTLSCertificateChain(t).Certificate[0]
	unrelatedDER := newTLSCertificateChain(t).Certificate[0]
	verifiedCertificate, err := x509.ParseCertificate(verifiedDER)
	require.NoError(t, err)
	unrelatedCertificate, err := x509.ParseCertificate(unrelatedDER)
	require.NoError(t, err)

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
	require.NoError(t, err)
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
		require.NoError(t, json.Unmarshal(views[0].TLS.Certificates[i], &certificate))
		assert.Equal(t, wantVerified, certificate.Verified, "certificate %d", i)
	}

	var output bytes.Buffer
	require.NoError(t, trace.writeText(&output, textdisplay.Options{}))
	assert.Contains(t, output.String(), "    handshake    "+views[0].TLS.Handshake+"\n")
	var certificateLines []string
	for line := range strings.SplitSeq(output.String(), "\n") {
		if strings.HasPrefix(line, "    certificate  ") {
			certificateLines = append(certificateLines, strings.TrimPrefix(line, "    certificate  "))
		}
	}
	require.Len(t, certificateLines, 2, "rendered peer certificates")
	for i, wantVerified := range []bool{true, false} {
		assert.Equal(t, string(views[0].TLS.Certificates[i]), certificateLines[i], "full certificate %d JSON", i)
		var certificate struct {
			Subject           string `json:"subject"`
			Issuer            string `json:"issuer"`
			SerialNumber      string `json:"serial_number"`
			SHA256Fingerprint string `json:"sha256_fingerprint"`
			Verified          bool   `json:"verified"`
		}
		require.NoError(t, json.Unmarshal([]byte(certificateLines[i]), &certificate), "rendered certificate %d JSON", i)
		assert.NotEmpty(t, certificate.Subject)
		assert.NotEmpty(t, certificate.Issuer)
		assert.NotEmpty(t, certificate.SerialNumber)
		assert.NotEmpty(t, certificate.SHA256Fingerprint)
		assert.Equal(t, wantVerified, certificate.Verified, "rendered certificate %d verification", i)
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

func TestHTTPHeadReportsShortHeaderWrite(t *testing.T) {
	t.Parallel()
	writer := &shortHTTPHeaderWriter{}
	err := writeHTTPHead(writer, &http.Response{Proto: "HTTP/1.1", Status: "200 OK", Header: http.Header{"X-Test": {"value"}}}, textdisplay.Options{})
	require.ErrorIs(t, err, io.ErrShortWrite)
	assert.Equal(t, 2, writer.calls, "stop after failed header")
}

type shortHTTPHeaderWriter struct{ calls int }

func (writer *shortHTTPHeaderWriter) Write(data []byte) (int, error) {
	writer.calls++
	if writer.calls == 2 {
		return 0, nil
	}
	return len(data), nil
}
