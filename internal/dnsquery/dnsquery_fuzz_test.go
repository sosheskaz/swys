package dnsquery_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"

	externalDNS "codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"

	"github.com/sosheskaz-systems/npc/internal/dnsquery"
)

const maxFuzzDNSWireSize = externalDNS.MaxMsgSize

func FuzzResolveWireResponse(f *testing.F) {
	matching := fuzzReplyFor(externalDNS.NewMsg("fuzz.example", externalDNS.TypeA))
	matching.Answer = []externalDNS.RR{&externalDNS.A{
		Hdr: externalDNS.Header{Name: "fuzz.example.", Class: externalDNS.ClassINET, TTL: 30},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}}
	f.Add(packFuzzDNSMessage(f, matching), uint8(0))
	for mismatch := uint8(1); mismatch <= 7; mismatch++ {
		f.Add(packFuzzDNSMessage(f, matching), mismatch)
	}
	emptyRDATA := fuzzReplyFor(externalDNS.NewMsg("fuzz.example", externalDNS.TypeANY))
	emptyRDATA.Answer = []externalDNS.RR{&externalDNS.OPT{
		Hdr: externalDNS.Header{Name: "fuzz.example.", Class: externalDNS.ClassINET, TTL: 30},
	}}
	f.Add(packFuzzDNSMessage(f, emptyRDATA), uint8(0))

	f.Fuzz(func(t *testing.T, wire []byte, mismatch uint8) {
		if len(wire) > maxFuzzDNSWireSize {
			t.Skip()
		}
		seedResponse := &externalDNS.Msg{Data: append([]byte(nil), wire...)}
		if err := seedResponse.Unpack(); err != nil || len(seedResponse.Question) != 1 {
			return
		}
		question := seedResponse.Question[0]
		recordType := externalDNS.RRToType(question)
		endpoint, err := dnsquery.ParseEndpoint("127.0.0.1", nil)
		if err != nil {
			t.Fatal(err)
		}
		var returned *externalDNS.Msg
		result, resolveErr := dnsquery.Resolve(t.Context(), dnsquery.Request{
			Resolver: dnsquery.ResolverDirect,
			Endpoint: &endpoint,
			Lookup:   question.Header().Name,
			Name:     question.Header().Name,
			Type:     recordType,
		}, dnsquery.Dependencies{
			ConfiguredServers: func() ([]string, error) { return nil, errUnexpectedConfiguredServers },
			PlaintextExchange: func(_ context.Context, request *externalDNS.Msg, _ dnsquery.Transport, _ string) (*externalDNS.Msg, error) {
				if mismatch%8 == 1 {
					return nil, nil //nolint:nilnil // A nil peer response is an intentional fuzz boundary.
				}
				returned = seedResponse.Copy()
				returned.ID = request.ID
				returned.Opcode = request.Opcode
				returned.Question = []externalDNS.RR{request.Question[0].Clone()}
				returned.Response = true
				mutateFuzzDNSResponse(returned, mismatch%8)
				return returned, nil
			},
		})
		if recordType == 0 || externalDNS.NewMsg(question.Header().Name, recordType) == nil {
			if !errors.Is(resolveErr, dnsquery.ErrInvalidRequest) {
				t.Fatalf("invalid generated query error=%v, want ErrInvalidRequest", resolveErr)
			}
			return
		}
		if mismatch%8 != 0 {
			if !errors.Is(resolveErr, dnsquery.ErrResponseMismatch) {
				t.Fatalf("mismatch=%d error=%v, want ErrResponseMismatch", mismatch%8, resolveErr)
			}
			return
		}
		if resolveErr != nil {
			t.Fatal(resolveErr)
		}
		if len(result.Answers) != len(returned.Answer) {
			t.Fatalf("answer count=%d want=%d", len(result.Answers), len(returned.Answer))
		}
		for index, record := range returned.Answer {
			wantValue := ""
			if data := record.Data(); data != nil {
				wantValue = data.String()
			}
			if result.Answers[index].Name != record.Header().Name || result.Answers[index].Value != wantValue {
				t.Fatalf("answer %d=%+v want name=%q value=%q", index, result.Answers[index], record.Header().Name, wantValue)
			}
		}
	})
}

func FuzzParseEndpointPortAgreement(f *testing.F) {
	for _, seed := range []struct {
		inlinePort uint32
		flagPort   uint32
		inline     bool
		explicit   bool
		ipv6       bool
	}{
		{},
		{flagPort: 53, explicit: true},
		{inlinePort: 53, inline: true, explicit: true, flagPort: 53},
		{inlinePort: 5353, inline: true, explicit: true, flagPort: 53},
		{inlinePort: 5353, inline: true, ipv6: true},
		{inlinePort: 0, inline: true},
		{inlinePort: 65536, inline: true},
	} {
		f.Add(seed.inlinePort, seed.flagPort, seed.inline, seed.explicit, seed.ipv6)
	}

	f.Fuzz(func(t *testing.T, inlinePort, flagPort uint32, inline, explicit, ipv6 bool) {
		host := "192.0.2.1"
		if ipv6 {
			host = "2001:db8::53"
		}
		raw := host
		if inline {
			raw = net.JoinHostPort(host, strconv.FormatUint(uint64(inlinePort), 10))
		}
		var explicitPort *uint16
		if explicit && flagPort <= 65535 {
			port := uint16(flagPort)
			explicitPort = &port
		}
		validInline := !inline || inlinePort >= 1 && inlinePort <= 65535
		validFlag := !explicit || flagPort >= 1 && flagPort <= 65535
		agree := !inline || !explicit || inlinePort == flagPort
		valid := validInline && validFlag && agree
		if explicit && flagPort > 65535 {
			// The typed API cannot represent an out-of-range explicit port; CLI parsing owns that case.
			return
		}
		endpoint, err := dnsquery.ParseEndpoint(raw, explicitPort)
		if !valid {
			if !errors.Is(err, dnsquery.ErrInvalidEndpoint) {
				t.Fatalf("raw=%q explicit=%d error=%v", raw, flagPort, err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		wantPort := uint32(53)
		switch {
		case inline:
			wantPort = inlinePort
		case explicit:
			wantPort = flagPort
		}
		wantAddress := net.JoinHostPort(host, strconv.FormatUint(uint64(wantPort), 10))
		if endpoint.Address() != wantAddress {
			t.Fatalf("Address()=%q want=%q", endpoint.Address(), wantAddress)
		}
	})
}

func mutateFuzzDNSResponse(response *externalDNS.Msg, mismatch uint8) {
	switch mismatch {
	case 2:
		response.Response = false
	case 3:
		response.ID++
	case 4:
		response.Opcode = (response.Opcode + 1) & 0xf
	case 5:
		response.Question[0].Header().Name = "mismatch.example."
	case 6:
		question := response.Question[0]
		replacementType := externalDNS.TypeNULL
		if externalDNS.RRToType(question) == externalDNS.TypeNULL {
			replacementType = externalDNS.TypeA
		}
		replacement := externalDNS.NewMsg(question.Header().Name, replacementType).Question[0]
		replacement.Header().Class = question.Header().Class
		response.Question[0] = replacement
	case 7:
		response.Question[0].Header().Class++
	}
}

func packFuzzDNSMessage(f *testing.F, message *externalDNS.Msg) []byte {
	f.Helper()
	if err := message.Pack(); err != nil {
		f.Fatal(err)
	}
	return append([]byte(nil), message.Data...)
}

func fuzzReplyFor(request *externalDNS.Msg) *externalDNS.Msg {
	response := new(externalDNS.Msg)
	dnsutil.SetReply(response, request)
	return response
}
