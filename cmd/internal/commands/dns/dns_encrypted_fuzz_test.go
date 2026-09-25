package dns_test

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
)

func FuzzEncryptedDNSEndpointNormalization(f *testing.F) {
	identity := newEncryptedDNSTestIdentity(f, []string{"localhost"}, nil)
	for _, seed := range []struct {
		token string
		mode  uint8
	}{
		{token: "simple", mode: 0},
		{token: "space and ? delimiter", mode: 1},
		{token: "user", mode: 2},
		{token: "fragment", mode: 3},
		{token: "", mode: 3},
		{token: "path", mode: 4},
		{token: "scheme", mode: 5},
		{token: "bracket", mode: 6},
		{token: "path", mode: 7},
		{token: "query", mode: 8},
		{token: "fragment", mode: 9},
		{token: "user", mode: 10},
	} {
		f.Add(seed.token, seed.mode)
	}
	f.Fuzz(func(t *testing.T, token string, mode uint8) {
		if len(token) > 64 {
			t.Skip()
		}
		server := startDoHTestServer(t, identity, false, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			message, err := readDoHTestRequest(request)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}
			writeDoHTestResponse(t, writer, standardDNSReply(message))
		}))
		var endpoint string
		valid := false
		switch mode % 11 {
		case 0:
			endpoint = server.endpoint("LOCALHOST", "")
			valid = true
		case 1:
			endpoint = server.endpoint("localhost", "/"+url.PathEscape(token)+"?token="+url.QueryEscape(token))
			valid = true
		case 2:
			endpoint = strings.Replace(server.endpoint("localhost", ""), "https://", "https://"+url.QueryEscape(token)+"@", 1)
		case 3:
			endpoint = server.endpoint("localhost", "/dns-query#"+url.PathEscape(token))
		case 4:
			endpoint = strings.Replace(server.endpoint("localhost", "/"+url.PathEscape(token)), "https://", "tls://", 1)
		case 5:
			endpoint = strings.Replace(server.endpoint("localhost", ""), "https://", "http://", 1)
		case 6:
			endpoint = "@https://[localhost:" + server.port() + "/dns-query"
		case 7:
			endpoint = "@127.0.0.1/" + url.PathEscape(token)
		case 8:
			endpoint = "@127.0.0.1?profile=" + url.QueryEscape(token)
		case 9:
			endpoint = "@127.0.0.1#" + url.PathEscape(token)
		case 10:
			endpoint = "@" + url.QueryEscape(token) + "@127.0.0.1"
		}
		args := []string{"dns", endpoint, "example.test", "--short", "--timeout", "1s"}
		if mode%11 < 7 {
			args = append(args, "--ca", identity.caCertPath)
		}
		stdout, _, err := executeRootStreams(t, args...)
		if valid {
			if err != nil || stdout != "192.0.2.44\n" {
				t.Fatalf("valid endpoint %q: stdout = %q, err = %v", endpoint, stdout, err)
			}
			return
		}
		if !errors.Is(err, errInvalidDNSOptions) {
			t.Fatalf("invalid endpoint %q error = %v, want invalid DNS options", endpoint, err)
		}
	})
}

func FuzzEncryptedDNSDoTFrameLengths(f *testing.F) {
	identity := newEncryptedDNSTestIdentity(f, []string{"localhost"}, nil)
	for _, seed := range []struct {
		delta   int16
		corrupt bool
	}{
		{delta: 0},
		{delta: -1},
		{delta: 1},
		{delta: -32768},
		{delta: 0, corrupt: true},
	} {
		f.Add(seed.delta, seed.corrupt)
	}
	f.Fuzz(func(t *testing.T, delta int16, corrupt bool) {
		endpoint := startDoTFrameFuzzServer(t, identity, delta, corrupt)
		outputPath := writeExistingDNSOutput(t)
		_, _, err := executeRootStreams(t, "dns", endpoint, "example.test", "--ca", identity.caCertPath, "--short", "--output", outputPath, "--timeout", "1s")
		if delta == 0 && !corrupt {
			if err != nil {
				t.Fatal(err)
			}
			data, readErr := os.ReadFile(outputPath)
			if readErr != nil || string(data) != "192.0.2.44\n" {
				t.Fatalf("output = %q, err = %v", data, readErr)
			}
			return
		}
		if err == nil {
			t.Fatalf("invalid frame delta=%d corrupt=%t succeeded", delta, corrupt)
		}
		assertExistingDNSOutput(t, outputPath)
	})
}

func FuzzEncryptedDNSDoHResponseBoundaries(f *testing.F) {
	identity := newEncryptedDNSTestIdentity(f, []string{"localhost"}, nil)
	for _, seed := range []struct {
		offset    int8
		truncated bool
	}{
		{offset: -1},
		{offset: 0},
		{offset: 1},
		{offset: 0, truncated: true},
	} {
		f.Add(seed.offset, seed.truncated)
	}
	f.Fuzz(func(t *testing.T, rawOffset int8, truncated bool) {
		offset := 0
		if rawOffset < 0 {
			offset = -1
		} else if rawOffset > 0 {
			offset = 1
		}
		size := dns.MaxMsgSize + offset
		server := startDoHTestServer(t, identity, false, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			message, err := readDoHTestRequest(request)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}
			responseSize, err := strconv.Atoi(request.URL.Query().Get("size"))
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}
			wire, err := packedDNSReplyOfSize(message, min(responseSize, dns.MaxMsgSize))
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}
			if request.URL.Query().Get("truncated") == "true" {
				wire = wire[:len(wire)-1]
			} else if responseSize > len(wire) {
				wire = append(wire, make([]byte, responseSize-len(wire))...)
			}
			writer.Header().Set("Content-Type", "application/dns-message")
			_, _ = writer.Write(wire) //nolint:errcheck // the client validates the resulting response
		}))
		endpoint := server.endpoint("localhost", fmt.Sprintf("/dns-query?size=%d&truncated=%t", size, truncated))
		outputPath := writeExistingDNSOutput(t)
		_, _, err := executeRootStreams(t, "dns", endpoint, "example.test", "--ca", identity.caCertPath, "--short", "--output", outputPath, "--timeout", "1s")
		if size <= dns.MaxMsgSize && !truncated {
			if err != nil {
				t.Fatal(err)
			}
			data, readErr := os.ReadFile(outputPath)
			if readErr != nil || string(data) != "192.0.2.44\n" {
				t.Fatalf("output = %q, err = %v", data, readErr)
			}
			return
		}
		if err == nil {
			t.Fatalf("size=%d truncated=%t succeeded", size, truncated)
		}
		assertExistingDNSOutput(t, outputPath)
	})
}

//nolint:gocritic // Identity is immutable fixture state.
func startDoTFrameFuzzServer(
	t *testing.T,
	identity encryptedDNSTestIdentity,
	delta int16,
	corrupt bool,
) string {
	t.Helper()
	baseListener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := tls.NewListener(baseListener, &tls.Config{Certificates: []tls.Certificate{identity.serverCert}, MinVersion: tls.VersionTLS12})
	t.Cleanup(func() { _ = listener.Close() }) //nolint:errcheck // test cleanup is best effort
	done := make(chan error, 1)
	t.Cleanup(func() {
		select {
		case serverErr := <-done:
			if serverErr != nil && !errors.Is(serverErr, net.ErrClosed) {
				t.Errorf("DoT fuzz server: %v", serverErr)
			}
		default:
		}
	})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer connection.Close() //nolint:errcheck // fuzz fixture cleanup is best effort
		reader := bufio.NewReader(connection)
		lengthBytes := make([]byte, 2)
		if _, readErr := io.ReadFull(reader, lengthBytes); readErr != nil {
			done <- readErr
			return
		}
		requestWire := make([]byte, int(binary.BigEndian.Uint16(lengthBytes)))
		if _, readErr := io.ReadFull(reader, requestWire); readErr != nil {
			done <- readErr
			return
		}
		request := &dns.Msg{Data: requestWire}
		if unpackErr := request.Unpack(); unpackErr != nil {
			done <- unpackErr
			return
		}
		response := standardDNSReply(request)
		if corrupt {
			response.Question = dns.NewMsg("other.test", dns.TypeA).Question
		}
		if packErr := response.Pack(); packErr != nil {
			done <- packErr
			return
		}
		advertised := len(response.Data) + int(delta)
		if advertised < 0 {
			advertised = 0
		}
		if advertised > dns.MaxMsgSize {
			advertised = dns.MaxMsgSize
		}
		frame := make([]byte, 2+len(response.Data))
		binary.BigEndian.PutUint16(frame, uint16(advertised))
		copy(frame[2:], response.Data)
		_, writeErr := connection.Write(frame)
		done <- writeErr
	}()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return "@tls://localhost:" + port
}
