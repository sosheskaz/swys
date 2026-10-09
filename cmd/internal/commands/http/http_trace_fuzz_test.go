package http

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/sosheskaz/swys/internal/textdisplay"
)

const maxFuzzHTTPTraceInputSize = 1 << 12

// forgedFuzzHTTPTraceURL smuggles a whole hop -- summary line and field line
// both -- so a renderer that stopped escaping the request target produces
// lines belonging to no real hop.
const forgedFuzzHTTPTraceURL = "https://example.test/\n" +
	"http trace 2: smuggled\n" +
	"  tls: forged-version, forged-cipher, alpn=x, verified=true"

// fuzzHTTPTraceFields are the indented labels writeText may emit, in the order
// it declares them. Re-derived here so a reordered or renamed field is a
// failure rather than a silently accepted change.
var fuzzHTTPTraceFields = []string{
	"network", "address", "connection", "attempt", "dns", "connect",
	"first byte", "transfer", "total", "version", "cipher", "alpn", "verified", "handshake", "certificate",
}

// FuzzHTTPTraceText checks that peer-supplied TLS metadata and request targets
// render as printable single lines. The trace summary carries the request URL
// and the negotiated version, cipher, and ALPN identifier, none of which the
// peer is obliged to keep printable; a smuggled newline would add a line that
// belongs to no hop, which the line classification below rejects.
//
// Timestamps are generated offsets from a fixed base and trace.finish() is
// never called, so the rendered timings are a deterministic function of the
// fuzz input.
func FuzzHTTPTraceText(f *testing.F) {
	f.Add("GET", "https://example.test/path", "TLS 1.3", "TLS_AES_128_GCM_SHA256", "👩‍💻", uint64(1), uint8(0x09), false, uint8(0))
	f.Add("GET", "https://example.test/path", "TLS 1.3", "TLS_AES_128_GCM_SHA256", "h2", uint64(0x0807060504030201), uint8(0x39), false, uint8(0))
	f.Add("GET", "https://example.test/two", "TLS 1.3", "TLS_AES_128_GCM_SHA256", "h2", uint64(0x0807060504030201), uint8(0x3a), false, uint8(0))
	f.Add("GET", "https://example.test/fallback", "TLS 1.3", "TLS_AES_128_GCM_SHA256", "h2", uint64(0x0807060504030201), uint8(0x79), false, uint8(0))
	// Descending stamps make every elapsed() field empty, so no timing line renders.
	f.Add("GET", "https://example.test/path", "TLS 1.3", "TLS_AES_128_GCM_SHA256", "h2", uint64(0x0102030405060708), uint8(0x39), false, uint8(0))
	f.Add("GET", "https://example.test/", "TLS 1.3", "TLS_AES_128_GCM_SHA256", "h2\nhttp trace 2: smuggled", uint64(1), uint8(0x09), false, uint8(0))
	f.Add("GET", "https://example.test/\nhttp trace 2: smuggled", "TLS 1.3", "c", "h2", uint64(1), uint8(0x01), false, uint8(0))
	f.Add("GET", "https://example.test/\nhttp trace 2: smuggled", "TLS 1.3", "c", "h2", uint64(1), uint8(0x09), false, uint8(0))
	// A phantom summary followed by a phantom field line: only reachable when
	// escaping is already broken, but it must still fail cleanly rather than
	// index past the real hops.
	f.Add("GET", forgedFuzzHTTPTraceURL, "TLS 1.3", "c", "h2", uint64(1), uint8(0x01), false, uint8(0))
	f.Add("GET\x00\x1b[2J", "https://example.test/", "TLS 1.3\r\n  dns: 0s", "c", "h2", uint64(1), uint8(0x09), false, uint8(0))
	f.Add("GET", "https://example.test/", "\xff\xfe", "\xff", "\xfe", uint64(1), uint8(0x09), false, uint8(0))
	f.Add("", "", "", "", "", uint64(0), uint8(0x09), false, uint8(0))
	f.Add("GET", "https://example.test/", "TLS 1.3", "c", "h2", uint64(0), uint8(0x04), false, uint8(0))
	f.Add("GET", "https://example.test/", "TLS 1.3", "c", "h2", uint64(0), uint8(0x00), false, uint8(0))
	for failureCall := range uint8(8) {
		f.Add("GET", "https://example.test/", "TLS 1.3", "c", "h2", uint64(0x0807060504030201), uint8(0x39), true, failureCall)
	}

	f.Fuzz(func(
		t *testing.T,
		method, url, tlsVersion, tlsCipher, tlsALPN string,
		timing uint64,
		shape uint8,
		outputFail bool,
		outputFailureCall uint8,
	) {
		if len(method)+len(url)+len(tlsVersion)+len(tlsCipher)+len(tlsALPN) > maxFuzzHTTPTraceInputSize {
			t.Skip()
		}
		trace := fuzzHTTPTrace(method, url, tlsVersion, tlsCipher, tlsALPN, timing, shape)

		baseline := &fuzzHTTPRecordingWriter{}
		if err := trace.writeText(baseline, textdisplay.Options{}); err != nil {
			t.Fatalf("write HTTP trace: %v", err)
		}
		if trace == nil && len(baseline.output) != 0 {
			t.Fatalf("nil trace wrote %q", baseline.output)
		}
		if outputFail && baseline.calls != 0 {
			output := &fuzzHTTPFailOnceWriter{failAt: int(outputFailureCall) % baseline.calls}
			if err := trace.writeText(output, textdisplay.Options{}); !errors.Is(err, errFuzzHTTPOutput) {
				t.Fatalf("trace error = %v, want output failure on call %d of %d", err, output.failAt, baseline.calls)
			}
			return
		}

		text := string(baseline.output)
		if !utf8.ValidString(text) {
			t.Fatalf("HTTP trace is not valid UTF-8: %x", text)
		}
		for _, char := range text {
			if char != '\n' && char != '\u200d' && !strconv.IsPrint(char) {
				t.Fatalf("HTTP trace contains non-printing rune %U: %q", char, text)
			}
		}
		if text != "" && !strings.HasSuffix(text, "\n") {
			t.Fatalf("HTTP trace %q does not end with a line break", text)
		}
		checkFuzzHTTPTraceLines(t, text, trace, method, url, tlsVersion, tlsCipher, tlsALPN)
	})
}

// checkFuzzHTTPTraceLines classifies every rendered line against the two shapes
// writeText may emit. A line belonging to neither means content escaped its
// field, which is exactly what escaping peer-controlled metadata prevents.
func checkFuzzHTTPTraceLines(t *testing.T, text string, trace *httpTrace, method, url, tlsVersion, tlsCipher, tlsALPN string) {
	t.Helper()
	var lines []string
	if text != "" {
		lines = strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	}
	hops := 0
	if trace != nil {
		hops = len(trace.hops)
	}

	hop := 0
	field := 0
	tlsLines := 0
	attemptLines := 0
	certificateLines := 0
	for _, line := range lines {
		if line == "" || line == "  Connection" || line == "  Timing" || line == "  TLS" {
			continue
		}
		if strings.HasPrefix(line, "http trace ") {
			checkFuzzHTTPTraceCounts(t, trace, hop, tlsLines, attemptLines, certificateLines, text)
			hop++
			field = 0
			tlsLines = 0
			attemptLines = 0
			certificateLines = 0
			prefix := fmt.Sprintf("http trace %d: ", hop)
			if !strings.HasPrefix(line, prefix) {
				t.Fatalf("summary line %q does not start with %q", line, prefix)
			}
			if isVerbatimDiagnosticValue(method) && isVerbatimDiagnosticValue(url) {
				if want := prefix + method + " " + url; line != want {
					t.Fatalf("summary line = %q, want %q", line, want)
				}
			}
			continue
		}
		if hop == 0 {
			t.Fatalf("line %q precedes any hop summary; trace %q", line, text)
		}
		next := fuzzHTTPTraceFieldIndex(line)
		if next < 0 {
			t.Fatalf("line %q matches no HTTP trace field; trace %q", line, text)
		}
		name := fuzzHTTPTraceFields[next]
		if name == "cipher" && isVerbatimDiagnosticValue(tlsCipher) && !strings.HasSuffix(line, "  "+tlsCipher) {
			t.Fatalf("cipher line = %q", line)
		}
		if name == "alpn" && isVerbatimDiagnosticValue(tlsALPN) && !strings.HasSuffix(line, "  "+tlsALPN) {
			t.Fatalf("ALPN line = %q", line)
		}
		if name == "verified" && hop <= len(trace.hops) && trace.hops[hop-1].tls != nil {
			want := fmt.Sprintf("  %t", trace.hops[hop-1].tls.verified)
			if !strings.HasSuffix(line, want) {
				t.Fatalf("verification line = %q, want %q", line, want)
			}
		}
		if next < field && (next != field-1 || (name != "attempt" && name != "certificate")) {
			t.Fatalf("field %q is out of declared order %q; trace %q", line, fuzzHTTPTraceFields, text)
		}
		field = next + 1
		if name == "attempt" {
			if hop <= len(trace.hops) {
				checkFuzzHTTPTraceAttempt(t, line, trace.hops[hop-1], attemptLines)
			}
			attemptLines++
		}
		if name == "certificate" {
			certificateLines++
		}
		if name == "version" {
			tlsLines++
			// A smuggled summary line can push hop past the real ones. That only
			// happens once production is already broken, and the trailing count
			// check reports it, so skip rather than index out of range.
			if hop <= len(trace.hops) {
				checkFuzzHTTPTraceTLSLine(t, line, trace.hops[hop-1], tlsVersion, tlsCipher, tlsALPN)
			}
		}
	}
	checkFuzzHTTPTraceCounts(t, trace, hop, tlsLines, attemptLines, certificateLines, text)
	if hop != hops {
		t.Fatalf("HTTP trace rendered %d summary lines, want %d hops: %q", hop, hops, text)
	}
}

// checkFuzzHTTPTraceCounts requires each captured attempt and TLS detail to render.
func checkFuzzHTTPTraceCounts(t *testing.T, trace *httpTrace, hop, tlsLines, attemptLines, certificateLines int, text string) {
	t.Helper()
	if hop == 0 || hop > len(trace.hops) {
		return
	}
	if want := len(trace.hops[hop-1].connectAttempts); attemptLines != want {
		t.Fatalf("hop %d rendered %d attempts, want %d: %q", hop, attemptLines, want, text)
	}
	want := 0
	if detail := trace.hops[hop-1].tls; detail != nil && detail.version != "" {
		want = 1
	}
	if tlsLines != want {
		t.Fatalf("hop %d rendered %d tls lines, want %d: %q", hop, tlsLines, want, text)
	}
	if trace.hops[hop-1].tls != nil {
		want = len(trace.hops[hop-1].tls.certificates)
	}
	if certificateLines != want {
		t.Fatalf("hop %d rendered %d certificate lines, want %d: %q", hop, certificateLines, want, text)
	}
}

func checkFuzzHTTPTraceAttempt(t *testing.T, line string, hop *httpTraceHop, index int) {
	t.Helper()
	if index >= len(hop.connectAttempts) {
		t.Fatalf("unexpected attempt line %q", line)
	}
	attempt := hop.connectAttempts[index]
	if !strings.Contains(line, attempt.network+" "+attempt.address) {
		t.Fatalf("attempt %d = %q, want network %q and address %q", index, line, attempt.network, attempt.address)
	}
	if strings.Contains(line, ", selected") != (attempt == hop.selectedConnect) {
		t.Fatalf("attempt %d = %q, want selected=%t", index, line, attempt == hop.selectedConnect)
	}
}

func checkFuzzHTTPTraceTLSLine(t *testing.T, line string, hop *httpTraceHop, tlsVersion, tlsCipher, tlsALPN string) {
	t.Helper()
	if hop.tls == nil {
		t.Fatalf("hop without TLS rendered %q", line)
	}
	if !isVerbatimDiagnosticValue(tlsVersion) || !isVerbatimDiagnosticValue(tlsCipher) || !isVerbatimDiagnosticValue(tlsALPN) {
		return
	}
	want := "  " + tlsVersion
	if !strings.HasSuffix(line, want) {
		t.Fatalf("TLS line = %q, want %q", line, want)
	}
}

func fuzzHTTPTraceFieldIndex(line string) int {
	for index, name := range fuzzHTTPTraceFields {
		if strings.HasPrefix(line, "    "+name+"  ") {
			return index
		}
	}
	return -1
}

// fuzzHTTPTrace builds a trace directly from generated values. Hop timestamps
// come from successive bytes of timing so degenerate hops -- zero, equal, and
// out-of-order stamps -- are reachable without wall-clock time.
func fuzzHTTPTrace(method, url, tlsVersion, tlsCipher, tlsALPN string, timing uint64, shape uint8) *httpTrace {
	if shape&0x04 != 0 {
		return nil
	}
	base := time.Unix(0, 0).UTC()
	stamp := func(offset uint64) time.Time {
		if offset == 0 {
			return time.Time{}
		}
		return base.Add(time.Duration(offset) * time.Microsecond)
	}

	trace := newHTTPTrace()
	for index := range int(shape & 0x03) {
		offsets := timing >> (index * 8)
		hop := &httpTraceHop{
			method: method, url: url, address: "203.0.113.1:443", network: "tcp", reused: "new",
			start:    stamp(offsets & 0xff),
			dnsStart: stamp(offsets >> 8 & 0xff), dnsDone: stamp(offsets >> 16 & 0xff),
			tlsStart: stamp(offsets >> 24 & 0xff), tlsDone: stamp(offsets >> 32 & 0xff),
			firstByte: stamp(offsets >> 40 & 0xff), end: stamp(offsets >> 48 & 0xff),
		}
		if shape&0x20 != 0 {
			hop.connectAttempts = []*httpTraceConnectAttempt{{
				start: hop.start, end: hop.tlsStart, network: "tcp", address: hop.address,
			}}
			if shape&0x40 != 0 {
				hop.connectAttempts = append([]*httpTraceConnectAttempt{{
					start: hop.start, end: hop.tlsStart, network: "tcp", address: "203.0.113.2:443", err: "refused",
				}}, hop.connectAttempts...)
			}
			hop.selectedConnect = hop.connectAttempts[len(hop.connectAttempts)-1]
		}
		if shape&0x08 != 0 {
			hop.tls = &httpTraceTLS{
				version: tlsVersion, cipher: tlsCipher, alpn: tlsALPN, verified: shape&0x10 != 0,
			}
		}
		trace.hops = append(trace.hops, hop)
	}
	return trace
}
