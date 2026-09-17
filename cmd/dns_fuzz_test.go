package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"

	"github.com/sosheskaz-systems/npc/internal/dnsquery"
)

const maxFuzzDNSWireSize = dns.MaxMsgSize

func FuzzDNSWireResultRendering(f *testing.F) {
	seedRequest := dns.NewMsg("fuzz.example", dns.TypeANY)
	seedResponse := replyFor(seedRequest)
	seedResponse.Answer = emptyRDATAAnswers()
	emptyRDATAWire := packFuzzDNSMessage(f, seedResponse)
	f.Add(emptyRDATAWire, uint8(0))

	compressed := replyFor(dns.NewMsg("compressed.fuzz.example", dns.TypeCNAME))
	compressed.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:   dns.Header{Name: "compressed.fuzz.example.", Class: dns.ClassINET, TTL: 1},
			CNAME: rdata.CNAME{Target: "target.fuzz.example."},
		},
		&dns.CNAME{
			Hdr:   dns.Header{Name: "second.fuzz.example.", Class: dns.ClassINET, TTL: 2},
			CNAME: rdata.CNAME{Target: "target.fuzz.example."},
		},
	}
	compressedWire := packFuzzDNSMessage(f, compressed)
	if !bytes.Contains(compressedWire[dns.MsgHeaderSize:], []byte{0xc0}) {
		f.Fatal("compressed DNS seed contains no compression pointer")
	}
	f.Add(compressedWire, uint8(0))
	f.Add(compressedWire, uint8(1))
	f.Add(compressedWire, uint8(2))
	f.Add(compressedWire, uint8(3))
	f.Add(compressedWire, uint8(4))
	f.Add(compressedWire, uint8(5))
	nameCollision := replyFor(dns.NewMsg("mismatch.example", dns.TypeA))
	f.Add(packFuzzDNSMessage(f, nameCollision), uint8(3))
	typeCollision := replyFor(dns.NewMsg("null.example", dns.TypeNULL))
	f.Add(packFuzzDNSMessage(f, typeCollision), uint8(4))
	nonResponse := dns.NewMsg("query.fuzz.example", dns.TypeA)
	f.Add(packFuzzDNSMessage(f, nonResponse), uint8(0))

	truncatedFlag := replyFor(dns.NewMsg("truncated.fuzz.example", dns.TypeA))
	truncatedFlag.Truncated = true
	f.Add(packFuzzDNSMessage(f, truncatedFlag), uint8(0))
	for _, length := range []int{0, 1, dns.MsgHeaderSize - 1, dns.MsgHeaderSize, len(compressedWire) - 1} {
		f.Add(append([]byte(nil), compressedWire[:length]...), uint8(0))
	}
	f.Add(append(append([]byte(nil), compressedWire...), 0), uint8(0))

	f.Fuzz(func(t *testing.T, wire []byte, mismatch uint8) {
		if len(wire) > maxFuzzDNSWireSize {
			t.Skip()
		}
		wireResponse := &dns.Msg{Data: append([]byte(nil), wire...)}
		if err := wireResponse.Unpack(); err != nil {
			return
		}
		if len(wireResponse.Question) != 1 {
			return
		}

		question := wireResponse.Question[0]
		recordType := dns.RRToType(question)
		endpoint, err := dnsquery.ParseEndpoint("127.0.0.1", nil)
		if err != nil {
			t.Fatal(err)
		}
		var returned *dns.Msg
		result, resolveErr := dnsquery.Resolve(t.Context(), dnsquery.Request{
			Resolver: dnsquery.ResolverDirect,
			Endpoint: &endpoint,
			Lookup:   question.Header().Name,
			Name:     question.Header().Name,
			Type:     recordType,
		}, dnsquery.Dependencies{
			ConfiguredServers: func() ([]string, error) { return nil, errUnexpectedConfiguredServerLookup },
			PlaintextExchange: func(_ context.Context, request *dns.Msg, _ dnsquery.Transport, _ string) (*dns.Msg, error) {
				returned = wireResponse.Copy()
				returned.ID = request.ID
				returned.Opcode = request.Opcode
				returned.Question = []dns.RR{request.Question[0].Clone()}
				mutateFuzzDNSResponse(returned, mismatch%6)
				return returned, nil
			},
		})
		if !wireResponse.Response || mismatch%6 != 0 {
			if !errors.Is(resolveErr, dnsquery.ErrResponseMismatch) {
				t.Fatalf("mismatch=%d validation error = %v, want ErrResponseMismatch", mismatch%6, resolveErr)
			}
			return
		}
		if resolveErr != nil {
			t.Fatal(resolveErr)
		}
		assertFuzzDNSResultMatchesMessage(t, &result, wireResponse)

		for _, format := range []string{dnsFormatText, dnsFormatJSON} {
			for _, short := range []bool{false, true} {
				output, err := renderDNSResult(&result, format, short)
				if err != nil {
					t.Fatalf("render format=%s short=%t: %v", format, short, err)
				}
				assertFuzzDNSRendering(t, output, &result, format, short)
			}
		}
	})
}

func mutateFuzzDNSResponse(response *dns.Msg, mismatch uint8) {
	switch mismatch {
	case 1:
		response.ID++
	case 2:
		response.Opcode = (response.Opcode + 1) & 0xf
	case 3:
		mismatchName := "mismatch.example."
		if strings.EqualFold(response.Question[0].Header().Name, mismatchName) {
			mismatchName = "other-mismatch.example."
		}
		response.Question[0].Header().Name = mismatchName
	case 4:
		question := response.Question[0]
		mismatchType := dns.TypeNULL
		if dns.RRToType(question) == dns.TypeNULL {
			mismatchType = dns.TypeA
		}
		replacement := dns.NewMsg(question.Header().Name, mismatchType).Question[0]
		replacement.Header().Class = question.Header().Class
		response.Question[0] = replacement
	case 5:
		response.Question[0].Header().Class++
	}
}

func packFuzzDNSMessage(f *testing.F, message *dns.Msg) []byte {
	f.Helper()
	if err := message.Pack(); err != nil {
		f.Fatal(err)
	}
	return append([]byte(nil), message.Data...)
}

func assertFuzzDNSResultMatchesMessage(t *testing.T, result *dnsquery.Result, response *dns.Msg) {
	t.Helper()
	if len(result.Answers) != len(response.Answer) {
		t.Fatalf("result answer count = %d, wire answer count = %d", len(result.Answers), len(response.Answer))
	}
	for index, record := range response.Answer {
		answer := result.Answers[index]
		wantValue := ""
		if data := record.Data(); data != nil {
			wantValue = data.String()
		}
		if answer.Name != record.Header().Name || answer.Value != wantValue {
			t.Fatalf("answer %d = %+v, want name %q value %q", index, answer, record.Header().Name, wantValue)
		}
		if answer.TTL == nil || *answer.TTL != record.Header().TTL {
			t.Fatalf("answer %d TTL = %v, want %d", index, answer.TTL, record.Header().TTL)
		}
	}
}

func assertFuzzDNSRendering(t *testing.T, output []byte, result *dnsquery.Result, format string, short bool) {
	t.Helper()
	if format == dnsFormatJSON {
		assertFuzzDNSJSONRendering(t, output, result, short)
		return
	}
	if !short && !strings.HasPrefix(string(output), ";; resolver: dns\n") {
		t.Fatalf("text output missing resolver header: %q", output)
	}
	if short && strings.Count(string(output), "\n") != len(result.Answers) {
		t.Fatalf("short text lines = %d, want %d: %q", strings.Count(string(output), "\n"), len(result.Answers), output)
	}
}

func assertFuzzDNSJSONRendering(t *testing.T, output []byte, result *dnsquery.Result, short bool) {
	t.Helper()
	if !short {
		var decoded dnsquery.Result
		if err := json.Unmarshal(output, &decoded); err != nil {
			t.Fatalf("decode JSON result: %v", err)
		}
		if len(decoded.Answers) != len(result.Answers) {
			t.Fatalf("JSON answer count = %d, want %d", len(decoded.Answers), len(result.Answers))
		}
		return
	}
	var values []string
	if err := json.Unmarshal(output, &values); err != nil {
		t.Fatalf("decode short JSON: %v", err)
	}
	if len(values) != len(result.Answers) {
		t.Fatalf("short JSON values = %d, want %d", len(values), len(result.Answers))
	}
	for index, answer := range result.Answers {
		// JSON replaces each invalid UTF-8 sequence with the replacement rune.
		want := string([]rune(answer.Value))
		if values[index] != want {
			t.Fatalf("short JSON value %d = %q, want %q", index, values[index], want)
		}
	}
}

func FuzzDNSServerPortParsing(f *testing.F) {
	for _, seed := range []struct {
		inlinePort uint32
		flagPort   uint32
		inline     bool
		explicit   bool
		ipv6       bool
		zeroPad    bool
	}{
		{inline: false, explicit: false},
		{flagPort: 1, explicit: true},
		{flagPort: 65535, explicit: true, ipv6: true},
		{inlinePort: 53, inline: true, zeroPad: true},
		{inlinePort: 5353, inline: true, ipv6: true},
		{inlinePort: 5353, flagPort: 5353, inline: true, explicit: true},
		{inlinePort: 5353, flagPort: 53, inline: true, explicit: true},
		{inlinePort: 0, inline: true},
		{inlinePort: 65536, inline: true},
	} {
		f.Add(seed.inlinePort, seed.flagPort, seed.inline, seed.explicit, seed.ipv6, seed.zeroPad)
	}

	f.Fuzz(func(t *testing.T, inlinePort, flagPort uint32, inline, explicit, ipv6, zeroPad bool) {
		host := "192.0.2.1"
		if ipv6 {
			host = "2001:db8::53"
		}
		server := host
		if inline {
			portText := strconv.FormatUint(uint64(inlinePort), 10)
			if zeroPad && len(portText) < 5 {
				portText = strings.Repeat("0", 5-len(portText)) + portText
			}
			server = net.JoinHostPort(host, portText)
		}

		validInline := !inline || inlinePort >= 1 && inlinePort <= 65535
		validFlag := !explicit || flagPort >= 1 && flagPort <= 65535
		agree := !inline || !explicit || inlinePort == flagPort
		valid := validInline && validFlag && agree
		wantPort := uint32(53)
		switch {
		case inline:
			wantPort = inlinePort
		case explicit:
			wantPort = flagPort
		}
		wantAddress := net.JoinHostPort(host, strconv.FormatUint(uint64(wantPort), 10))

		exchanged := false
		gotAddress := ""
		root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
			PlaintextExchange: func(_ context.Context, request *dns.Msg, _ dnsquery.Transport, address string) (*dns.Msg, error) {
				exchanged = true
				gotAddress = address
				return replyFor(request), nil
			},
			ConfiguredServers: func() ([]string, error) { return nil, errUnexpectedConfiguredServerLookup },
		})
		args := []string{"dns", "@" + server, "fuzz.example"}
		if explicit {
			args = append(args, "--port", strconv.FormatUint(uint64(flagPort), 10))
		}
		_, _, err := executeRootCommandStreams(t, root, args...)
		if valid {
			if err != nil {
				t.Fatalf("valid endpoint %q port=%d explicit=%t: %v", server, flagPort, explicit, err)
			}
			if !exchanged || gotAddress != wantAddress {
				t.Fatalf("exchange = %t address %q, want %q", exchanged, gotAddress, wantAddress)
			}
			return
		}
		if !errors.Is(err, errInvalidDNSOptions) {
			t.Fatalf("invalid endpoint %q port=%d explicit=%t error = %v, want errInvalidDNSOptions", server, flagPort, explicit, err)
		}
		if exchanged {
			t.Fatal("invalid endpoint reached DNS exchange")
		}
	})
}

func FuzzDNSMalformedServerSyntax(f *testing.F) {
	for kind := range uint8(7) {
		f.Add(uint16(53), kind)
	}
	f.Fuzz(func(t *testing.T, number uint16, kind uint8) {
		port := strconv.FormatUint(uint64(number), 10)
		component := strconv.FormatUint(uint64(number), 16)
		// Each construction violates a delimiter rule independently of port validity.
		servers := []string{
			"192.0.2.1:" + port + ":53",
			"host:" + port + ":53",
			"[2001:db8::" + component,
			"2001:db8::" + component + "]",
			"[" + component + ":b:c",
			"[2001:db8::1]:" + port + ":53",
			"[" + component + ":b:c]:53",
		}
		server := servers[int(kind)%len(servers)]
		exchanged := false
		root := newRootCmdWithDNSDependencies(dnsquery.Dependencies{
			PlaintextExchange: func(_ context.Context, request *dns.Msg, _ dnsquery.Transport, _ string) (*dns.Msg, error) {
				exchanged = true
				return replyFor(request), nil
			},
			ConfiguredServers: func() ([]string, error) { return nil, errUnexpectedConfiguredServerLookup },
		})
		_, _, err := executeRootCommandStreams(t, root, "dns", "@"+server, "fuzz.example", "--port", "53")
		if !errors.Is(err, errInvalidDNSOptions) {
			t.Fatalf("malformed endpoint %q: error=%v", server, err)
		}
		if exchanged {
			t.Fatal("malformed endpoint reached exchange")
		}
	})
}
