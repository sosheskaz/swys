package http

import (
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func FuzzHTTPField(f *testing.F) {
	for _, seed := range []string{"name=value", "name=", "=value", "name", "line\r\nbreak=value", "unicode=José", "nul\x00=value", "del\x7f=value"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, field string) {
		if len(field) > 4<<10 {
			t.Skip()
		}
		wantName, wantValue, exists := strings.Cut(field, "=")
		valid := exists && wantName != "" && referenceHTTPHeaderValue(wantName)
		name, value, err := httpField(field)
		if (err == nil) != valid {
			t.Fatalf("field %q acceptance = %v, want valid %t", field, err, valid)
		}
		if !valid {
			return
		}
		if name != wantName || value != wantValue {
			t.Fatalf("field %q parsed as %q=%q, want %q=%q", field, name, value, wantName, wantValue)
		}

		body, err := httpFormBody([]string{field})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := io.ReadAll(body)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := url.ParseQuery(string(encoded))
		if err != nil {
			t.Fatal(err)
		}
		values, ok := parsed[name]
		if !ok || len(values) != 1 || values[0] != value {
			t.Fatalf("form round trip = %q, want %q=%q", parsed, name, value)
		}
	})
}

func FuzzParseHTTPHeaders(f *testing.F) {
	f.Add("X-Test: value", "Host: example.com", true)
	f.Add("Host: one", "host: two", true)
	f.Add("Content-Length: 1", "", false)
	f.Add("X-Test: good\r\nInjected: bad", "", false)
	f.Add("Empty:", "", false)

	f.Fuzz(func(t *testing.T, first, second string, includeSecond bool) {
		if len(first)+len(second) > 8<<10 {
			t.Skip()
		}
		values := []string{first}
		if includeSecond {
			values = append(values, second)
		}
		want, valid := referenceHTTPHeaders(values)
		got, err := parseHTTPHeaders(values)
		if (err == nil) != valid {
			t.Fatalf("headers %q acceptance = %v, want valid %t", values, err, valid)
		}
		if valid && !reflect.DeepEqual(got, want) {
			t.Fatalf("headers %q = %#v, want %#v", values, got, want)
		}
		if !valid && got != nil {
			t.Fatalf("invalid headers returned partial map %#v", got)
		}
	})
}

func referenceHTTPHeaders(values []string) (http.Header, bool) {
	headers := make(http.Header)
	for _, value := range values {
		name, content, exists := strings.Cut(value, ":")
		if !exists || !referenceHTTPToken(name) || !referenceHTTPHeaderValue(content) {
			return nil, false
		}
		if strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Transfer-Encoding") {
			return nil, false
		}
		headers.Add(name, strings.TrimSpace(content))
	}
	if len(headers.Values("Host")) > 1 {
		return nil, false
	}
	return headers, true
}

func referenceHTTPToken(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		alphaNumeric := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
		if alphaNumeric || strings.ContainsRune("!#$%&'*+-.^_`|~", char) {
			continue
		}
		return false
	}
	return true
}

func referenceHTTPHeaderValue(value string) bool {
	for _, char := range value {
		if char < ' ' && char != '\t' || char == 127 {
			return false
		}
	}
	return true
}
