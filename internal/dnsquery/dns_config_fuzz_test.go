//go:build !windows

package dnsquery

import (
	"bufio"
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode"
)

// maxFuzzResolvConfSize keeps generated configs at twice the scanner token
// limit so the oversized-line boundary stays reachable without unbounded
// per-iteration cost.
const maxFuzzResolvConfSize = bufio.MaxScanTokenSize * 2

// FuzzParseConfiguredDNSServers parses generated /etc/resolv.conf bytes — an
// OS-owned file whose contents swys does not control — and re-derives the
// expected server list with an independently structured line tokenizer.
// Lines shorter than the scanner token limit must yield exactly the second
// field of every nameserver line, in order; any raw line at or beyond the
// 64 KiB bufio.Scanner limit must fail the whole discovery instead of
// silently skipping or truncating servers.
func FuzzParseConfiguredDNSServers(f *testing.F) {
	f.Add([]byte("nameserver 192.0.2.1\nnameserver 2001:db8::53\nsearch example.org\n"))
	f.Add([]byte("# comment\n\nnameserver\t\t10.0.0.1  extra\n"))
	f.Add([]byte("nameserver\nsearch gap between\nnameserver 192.0.2.53"))
	f.Add([]byte("  nameserver 1.1.1.1\r\nnameserver 9.9.9.9\r\n"))
	f.Add([]byte("nameserver 192.0.2.1\r junk\n"))
	f.Add([]byte("\x00\xfftwo\x01fields nameserver"))
	f.Add([]byte(strings.Repeat("nameserver 192.0.2.1\n", 16)))
	f.Add([]byte(strings.Repeat("x", bufio.MaxScanTokenSize-1) + "\n"))
	f.Add([]byte(strings.Repeat("x", bufio.MaxScanTokenSize-1)))
	f.Add([]byte(strings.Repeat("x", bufio.MaxScanTokenSize-1) + "\r\n"))
	f.Add([]byte(strings.Repeat("x", bufio.MaxScanTokenSize) + "\n"))
	f.Add([]byte(strings.Repeat("x", bufio.MaxScanTokenSize)))
	f.Add([]byte("#" + strings.Repeat("y", bufio.MaxScanTokenSize) + "\nnameserver 192.0.2.1\n"))
	f.Add([]byte(strings.Repeat("nameserver 192.0.2.254 ", 3400) + "\n"))

	f.Fuzz(func(t *testing.T, config []byte) {
		if len(config) > maxFuzzResolvConfSize {
			t.Skip()
		}

		wantServers, tooLong := fuzzResolvConfOracle(config)
		servers, err := parseConfiguredDNSServers(bytes.NewReader(config))
		if tooLong {
			if !errors.Is(err, bufio.ErrTooLong) {
				t.Fatalf("oversized line error = %v, want bufio.ErrTooLong", err)
			}
			if servers != nil {
				t.Fatalf("oversized line returned %v servers, want none", servers)
			}
			return
		}
		if err != nil {
			t.Fatalf("parse resolv.conf = %v, want success", err)
		}
		if !reflect.DeepEqual(servers, wantServers) {
			t.Fatalf("servers = %v, want %v", servers, wantServers)
		}
	})
}

// fuzzResolvConfOracle re-derives discovery expectations without bufio: raw
// lines are the byte spans between newlines (the final span may be
// unterminated), the scanner token drops one trailing carriage return, and
// fields split on unicode whitespace.
func fuzzResolvConfOracle(config []byte) ([]string, bool) {
	var servers []string
	tooLong := false
	data := config
	for len(data) > 0 {
		var raw []byte
		if index := bytes.IndexByte(data, '\n'); index >= 0 {
			raw, data = data[:index], data[index+1:]
		} else {
			raw, data = data, nil
		}
		// bufio fills its whole 64 KiB buffer before it can observe the
		// newline that ends a line, so the limit applies to the raw span,
		// including any carriage return.
		if len(raw) >= bufio.MaxScanTokenSize {
			tooLong = true
		}
		token := raw
		if bytes.HasSuffix(token, []byte("\r")) {
			token = token[:len(token)-1]
		}
		fields := strings.FieldsFunc(string(token), unicode.IsSpace)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			servers = append(servers, fields[1])
		}
	}
	return servers, tooLong
}
