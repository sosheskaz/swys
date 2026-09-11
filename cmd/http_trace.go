package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"

	"github.com/sosheskaz-systems/npc/internal/asym"
)

type httpTrace struct {
	hops []*httpTraceHop
	mu   sync.Mutex
}

type httpTraceHop struct { //nolint:govet // Grouping timestamps makes callback updates and timing derivation auditable.
	tls                                   *httpTraceTLS
	selectedConnect                       *httpTraceConnectAttempt
	connectAttempts                       []*httpTraceConnectAttempt
	method, url, address, network, reused string
	start, dnsStart, dnsDone, tlsStart    time.Time
	tlsDone, firstByte, end               time.Time
}

type httpTraceConnectAttempt struct {
	start, end       time.Time
	network, address string
	err              string
}

type httpTraceTLS struct { //nolint:govet // Grouping TLS labels keeps snapshot construction readable.
	certificates          []*asym.CertInfo
	version, cipher, alpn string
	verified              bool
}

type httpTraceView struct { //nolint:govet // Field order keeps timing JSON in its documented reading order.
	Method     string                 `json:"method"`
	URL        string                 `json:"url"`
	Address    string                 `json:"address,omitempty"`
	Network    string                 `json:"network,omitempty"`
	Connection string                 `json:"connection,omitempty"`
	DNS        string                 `json:"dns,omitempty"`
	Connect    string                 `json:"connect,omitempty"`
	Attempts   []httpTraceConnectView `json:"connect_attempts,omitempty"`
	TLS        *httpTraceTLSView      `json:"tls,omitempty"`
	FirstByte  string                 `json:"first_byte,omitempty"`
	Transfer   string                 `json:"transfer,omitempty"`
	Total      string                 `json:"total,omitempty"`
}

type httpTraceConnectView struct {
	Network  string `json:"network"`
	Address  string `json:"address"`
	Duration string `json:"duration,omitempty"`
	Error    string `json:"error,omitempty"`
	Selected bool   `json:"selected"`
}

type httpTraceTLSView struct { //nolint:govet // Field order keeps the human-oriented JSON representation stable.
	Version      string            `json:"version"`
	Cipher       string            `json:"cipher"`
	ALPN         string            `json:"alpn,omitempty"`
	Verified     bool              `json:"verified"`
	Handshake    string            `json:"handshake,omitempty"`
	Certificates []json.RawMessage `json:"certificates,omitempty"`
}

func newHTTPTrace() *httpTrace { return &httpTrace{} }

func (trace *httpTrace) roundTrip(request *http.Request, transport http.RoundTripper) (*http.Response, error) {
	hop := &httpTraceHop{start: time.Now(), method: request.Method, url: request.URL.Redacted()}
	trace.mu.Lock()
	trace.finishLocked(hop.start)
	trace.hops = append(trace.hops, hop)
	trace.mu.Unlock()

	setTime := func(target *time.Time) { trace.mu.Lock(); *target = time.Now(); trace.mu.Unlock() }
	clientTrace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { setTime(&hop.dnsStart) },
		DNSDone:  func(httptrace.DNSDoneInfo) { setTime(&hop.dnsDone) },
		ConnectStart: func(network, address string) {
			trace.mu.Lock()
			hop.connectAttempts = append(hop.connectAttempts, &httpTraceConnectAttempt{
				start: time.Now(), network: network, address: address,
			})
			trace.mu.Unlock()
		},
		ConnectDone: func(network, address string, connectErr error) {
			trace.mu.Lock()
			if attempt := unfinishedConnectAttempt(hop.connectAttempts, network, address); attempt != nil {
				attempt.end = time.Now()
				if connectErr != nil {
					attempt.err = connectErr.Error()
				}
			}
			trace.mu.Unlock()
		},
		TLSHandshakeStart: func() { setTime(&hop.tlsStart) },
		TLSHandshakeDone: func(state tls.ConnectionState, _ error) {
			certificates := make([]*asym.CertInfo, len(state.PeerCertificates))
			verified := len(state.VerifiedChains) > 0
			for i, certificate := range state.PeerCertificates {
				certificates[i] = asym.NewCertInfo(certificate)
				certificates[i].Verified = certificateInVerifiedChains(certificate, state.VerifiedChains)
			}
			trace.mu.Lock()
			hop.tlsDone = time.Now()
			hop.tls = &httpTraceTLS{
				version: tls.VersionName(state.Version), cipher: tls.CipherSuiteName(state.CipherSuite),
				alpn: state.NegotiatedProtocol, verified: verified, certificates: certificates,
			}
			trace.mu.Unlock()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			trace.mu.Lock()
			if info.Reused {
				hop.reused = "reused"
			} else {
				hop.reused = "new"
			}
			if info.Conn != nil {
				hop.address = info.Conn.RemoteAddr().String()
				hop.selectedConnect = connectAttemptForAddress(hop.connectAttempts, hop.address)
				if hop.selectedConnect != nil {
					hop.network = hop.selectedConnect.network
				}
			}
			trace.mu.Unlock()
		},
		GotFirstResponseByte: func() { setTime(&hop.firstByte) },
	}
	response, err := transport.RoundTrip(request.WithContext(httptrace.WithClientTrace(request.Context(), clientTrace)))
	if err != nil {
		trace.mu.Lock()
		hop.end = time.Now()
		trace.mu.Unlock()
	}
	if err != nil {
		return response, fmt.Errorf("perform traced HTTP round trip: %w", err)
	}
	return response, nil
}

func unfinishedConnectAttempt(attempts []*httpTraceConnectAttempt, network, address string) *httpTraceConnectAttempt {
	for i := len(attempts) - 1; i >= 0; i-- {
		attempt := attempts[i]
		if attempt.network == network && attempt.address == address && attempt.end.IsZero() {
			return attempt
		}
	}
	return nil
}

func connectAttemptForAddress(attempts []*httpTraceConnectAttempt, address string) *httpTraceConnectAttempt {
	for i := len(attempts) - 1; i >= 0; i-- {
		if attempts[i].address == address {
			return attempts[i]
		}
	}
	return nil
}

func certificateInVerifiedChains(certificate *x509.Certificate, chains [][]*x509.Certificate) bool {
	for _, chain := range chains {
		for _, verifiedCertificate := range chain {
			if bytes.Equal(certificate.Raw, verifiedCertificate.Raw) {
				return true
			}
		}
	}
	return false
}

func (trace *httpTrace) finish() {
	if trace == nil {
		return
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	trace.finishLocked(time.Now())
}

func (trace *httpTrace) finishLocked(now time.Time) {
	if len(trace.hops) != 0 && trace.hops[len(trace.hops)-1].end.IsZero() {
		trace.hops[len(trace.hops)-1].end = now
	}
}

func (trace *httpTrace) views() []httpTraceView {
	if trace == nil {
		return nil
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	views := make([]httpTraceView, 0, len(trace.hops))
	for _, hop := range trace.hops {
		view := httpTraceView{Method: hop.method, URL: hop.url, Address: hop.address, Network: hop.network, Connection: hop.reused}
		view.DNS = elapsed(hop.dnsStart, firstNonZero(hop.dnsDone, firstConnectStart(hop.connectAttempts), hop.tlsStart, hop.firstByte, hop.end))
		selected := hop.selectedConnect
		if selected == nil {
			selected = firstCompletedConnectAttempt(hop.connectAttempts)
		}
		if selected != nil {
			view.Connect = elapsed(selected.start, firstNonZero(selected.end, hop.tlsStart, hop.firstByte, hop.end))
		}
		view.Attempts = connectAttemptViews(hop.connectAttempts, hop.selectedConnect)
		view.FirstByte = elapsed(hop.start, hop.firstByte)
		view.Transfer = elapsed(hop.firstByte, hop.end)
		view.Total = elapsed(hop.start, hop.end)
		if hop.tls != nil {
			certificates := make([]json.RawMessage, 0, len(hop.tls.certificates))
			for _, certificate := range hop.tls.certificates {
				var output bytes.Buffer
				if err := (&asym.JSONFormatter{}).Format(certificate, &output); err == nil {
					certificates = append(certificates, bytes.TrimSpace(output.Bytes()))
				}
			}
			view.TLS = &httpTraceTLSView{
				Version: hop.tls.version, Cipher: hop.tls.cipher, ALPN: hop.tls.alpn,
				Verified: hop.tls.verified, Handshake: elapsed(hop.tlsStart, firstNonZero(hop.tlsDone, hop.firstByte, hop.end)),
				Certificates: certificates,
			}
		}
		views = append(views, view)
	}
	return views
}

func firstConnectStart(attempts []*httpTraceConnectAttempt) time.Time {
	if len(attempts) == 0 {
		return time.Time{}
	}
	return attempts[0].start
}

func firstCompletedConnectAttempt(attempts []*httpTraceConnectAttempt) *httpTraceConnectAttempt {
	for _, attempt := range attempts {
		if !attempt.end.IsZero() {
			return attempt
		}
	}
	return nil
}

func connectAttemptViews(attempts []*httpTraceConnectAttempt, selected *httpTraceConnectAttempt) []httpTraceConnectView {
	views := make([]httpTraceConnectView, 0, len(attempts))
	for _, attempt := range attempts {
		views = append(views, httpTraceConnectView{
			Network: attempt.network, Address: attempt.address, Duration: elapsed(attempt.start, attempt.end),
			Error: attempt.err, Selected: attempt == selected,
		})
	}
	return views
}

func elapsed(start, end time.Time) string {
	if start.IsZero() || end.IsZero() || end.Before(start) {
		return ""
	}
	return end.Sub(start).Round(time.Microsecond).String()
}

func firstNonZero(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}

func (trace *httpTrace) writeText(output io.Writer) error {
	views := trace.views()
	for i := range views {
		view := &views[i]
		if _, err := fmt.Fprintf(output, "http trace %d: %s %s\n", i+1, asym.EscapeDiagnosticValue(view.Method), asym.EscapeDiagnosticValue(view.URL)); err != nil {
			return fmt.Errorf("write HTTP trace summary: %w", err)
		}
		fields := []struct{ name, value string }{
			{name: "dns", value: view.DNS},
			{name: "connect", value: view.Connect},
			{name: "first byte", value: view.FirstByte},
			{name: "transfer", value: view.Transfer},
			{name: "total", value: view.Total},
		}
		for _, field := range fields {
			if field.value != "" {
				if _, err := fmt.Fprintf(output, "  %s: %s\n", field.name, field.value); err != nil {
					return fmt.Errorf("write HTTP trace timing: %w", err)
				}
			}
		}
		if view.TLS != nil {
			if _, err := fmt.Fprintf(
				output, "  tls: %s, %s, alpn=%s, verified=%t\n",
				asym.EscapeDiagnosticValue(view.TLS.Version), asym.EscapeDiagnosticValue(view.TLS.Cipher),
				asym.EscapeDiagnosticValue(view.TLS.ALPN), view.TLS.Verified,
			); err != nil {
				return fmt.Errorf("write HTTP TLS trace: %w", err)
			}
		}
	}
	return nil
}
