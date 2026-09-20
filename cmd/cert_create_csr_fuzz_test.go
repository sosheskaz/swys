package cmd

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"testing"
	"testing/iotest"
)

const maxCSRIssueFuzzInputSize = 64 << 10

var errCSRIssueFuzzOracle = errors.New("CSR issuance fuzz oracle rejected input")

func FuzzCertCreateCSRStrictInput(f *testing.F) {
	fixture := newCSRIssueFixture(f)
	validDER := createCSRIssueRequest(f, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "fuzz.example", Organization: []string{"npc"}},
		DNSNames:    []string{"fuzz.example"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.50")},
	})
	validPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: validDER})
	newPEM := pem.EncodeToMemory(&pem.Block{Type: "NEW CERTIFICATE REQUEST", Bytes: validDER})
	markerDER := createCSRIssueRequest(f, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "identity-----BEGINmarker"},
	})
	markerPEM := pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE REQUEST",
		Headers: map[string]string{"Comment": "ordinary -----BEGIN marker"},
		Bytes:   markerDER,
	})
	badSignature := bytes.Clone(validDER)
	badSignature[len(badSignature)-1] ^= 0x01
	badLength := bytes.Clone(validDER)
	badLength[1] = 0xff
	unsupportedDER := createCSRIssueRequest(f, requestWithCSRIssueExtension(csrIssueOIDUnsupported))
	duplicateDER := createCSRIssueRequest(f, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "duplicate.example"},
		ExtraExtensions: []pkix.Extension{
			{Id: csrIssueOIDSubjectAltName, Value: []byte{0x30, 0x00}},
			{Id: csrIssueOIDSubjectAltName, Value: []byte{0x30, 0x00}},
		},
	})
	constructedDNSDER := createCSRIssueRequest(f, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "constructed.example"},
		ExtraExtensions: []pkix.Extension{{
			Id:    csrIssueOIDSubjectAltName,
			Value: []byte{0x30, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x61},
		}},
	})
	emptySANDER := createCSRIssueRequest(f, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "empty-san.example"},
		ExtraExtensions: []pkix.Extension{{
			Id:    csrIssueOIDSubjectAltName,
			Value: []byte{0x30, 0x00},
		}},
	})
	emptySAN := pkix.AttributeTypeAndValue{Type: csrIssueOIDSubjectAltName, Value: []byte{0x30, 0x00}}
	multipleExtensionRequestValuesDER := createCSRIssueRequest(f, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "duplicate-values.example"},
		Attributes: []pkix.AttributeTypeAndValueSET{{ //nolint:staticcheck // Only this legacy field can encode multiple extensionRequest SET values.
			Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14},
			Value: [][]pkix.AttributeTypeAndValue{{emptySAN}, {emptySAN}},
		}},
	})
	malformedExtensionRequestDER := createMalformedCSRIssueExtensionRequest(f)
	malformedFirst := append(
		[]byte("-----BEGIN CERTIFICATE REQUEST-----\n!\n-----END CERTIFICATE REQUEST-----\n"),
		validPEM...,
	)
	for _, seed := range [][]byte{
		validDER,
		validPEM,
		newPEM,
		markerDER,
		markerPEM,
		validDER[:len(validDER)-1],
		badSignature,
		badLength,
		unsupportedDER,
		duplicateDER,
		constructedDNSDER,
		emptySANDER,
		multipleExtensionRequestValuesDER,
		malformedExtensionRequestDER,
		append(bytes.Clone(validDER), 0x00),
		append(bytes.Clone(validPEM), []byte("trailing")...),
		append([]byte("garbage\n"), validPEM...),
		append(bytes.Clone(validPEM), validPEM...),
		malformedFirst,
		{},
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxCSRIssueFuzzInputSize {
			t.Skip()
		}
		request, parseErr := parseCSRIssueStrictOracle(data)
		wantSuccess := parseErr == nil && supportedCSRIssueRequestOracle(request)

		for _, oneByte := range []bool{false, true} {
			reader := bytes.NewReader(data)
			input := iotest.OneByteReader(reader)
			if !oneByte {
				input = reader
			}
			stdout, _, runErr := executeRootStreamsWithInput(t, input, fixture.issueArgs("-")...)
			if (runErr == nil) != wantSuccess {
				t.Fatalf("oneByte=%t parseErr=%v supported=%t runErr=%v", oneByte, parseErr, request != nil && supportedCSRIssueRequestOracle(request), runErr)
			}
			if runErr != nil {
				if stdout != "" {
					t.Fatalf("oneByte=%t failed issuance wrote %q", oneByte, stdout)
				}
				continue
			}
			certificate := parseCSRIssueCertificatePEM(t, []byte(stdout))
			if err := certificate.CheckSignatureFrom(fixture.ca); err != nil {
				t.Fatalf("oneByte=%t issuer signature: %v", oneByte, err)
			}
			assertCSRIssueCertificateMatchesRequest(t, certificate, request)
		}
	})
}

func parseCSRIssueStrictOracle(data []byte) (*x509.CertificateRequest, error) {
	trimmed := bytes.TrimSpace(data)
	der := data
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		block, rest, err := decodeCSRIssueFirstPEMOracle(trimmed)
		if err != nil {
			return nil, err
		}
		if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
			return nil, fmt.Errorf("%w: unexpected PEM type %q", errCSRIssueFuzzOracle, block.Type)
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("%w: trailing PEM data", errCSRIssueFuzzOracle)
		}
		der = block.Bytes
	}
	request, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("parse CSR DER: %w", err)
	}
	return request, nil
}

func decodeCSRIssueFirstPEMOracle(data []byte) (*pem.Block, []byte, error) {
	if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
		return nil, data, fmt.Errorf("%w: missing PEM begin line", errCSRIssueFuzzOracle)
	}
	end := len(data)
	if next := bytes.Index(data, []byte("\n-----BEGIN ")); next >= 0 {
		end = next + 1
	}
	candidate := maskCSRIssuePEMHeaderMarkersOracle(data[:end])
	block, rest := pem.Decode(candidate)
	if block == nil {
		return nil, data, fmt.Errorf("%w: malformed first PEM block", errCSRIssueFuzzOracle)
	}
	return block, data[end-len(rest):], nil
}

func maskCSRIssuePEMHeaderMarkersOracle(data []byte) []byte {
	masked := bytes.Clone(data)
	lineStart := bytes.IndexByte(masked, '\n') + 1
	if lineStart == 0 {
		return masked
	}
	for lineStart < len(masked) {
		lineEnd := bytes.IndexByte(masked[lineStart:], '\n')
		if lineEnd < 0 {
			lineEnd = len(masked) - lineStart
		}
		line := masked[lineStart : lineStart+lineEnd]
		if len(bytes.TrimSpace(line)) == 0 {
			break
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			break
		}
		value := line[colon+1:]
		for marker := bytes.Index(value, []byte("-----BEGIN ")); marker >= 0; marker = bytes.Index(value, []byte("-----BEGIN ")) {
			copy(value[marker:marker+len("-----BEGIN ")], "_____BEGIN ")
			value = value[marker+len("-----BEGIN "):]
		}
		lineStart += lineEnd + 1
	}
	return masked
}

func supportedCSRIssueRequestOracle(request *x509.CertificateRequest) bool {
	if request == nil || request.CheckSignature() != nil {
		return false
	}
	if !unambiguousCSRIssueExtensionRequestsOracle(request) {
		return false
	}
	if len(request.EmailAddresses) != 0 || len(request.URIs) != 0 {
		return false
	}
	for _, extension := range request.Extensions {
		if !extension.Id.Equal(csrIssueOIDSubjectAltName) || !supportedCSRIssueSANOracle(extension.Value) {
			return false
		}
	}
	if len(request.Subject.Names) == 0 && len(request.DNSNames) == 0 && len(request.IPAddresses) == 0 {
		return false
	}
	_, err := x509.MarshalPKIXPublicKey(request.PublicKey)
	return err == nil
}

func unambiguousCSRIssueExtensionRequestsOracle(request *x509.CertificateRequest) bool {
	var info struct { //nolint:govet // Field order is the signed PKCS #10 ASN.1 sequence.
		Version       int
		Subject       asn1.RawValue
		PublicKey     asn1.RawValue
		RawAttributes []asn1.RawValue `asn1:"tag:0"`
	}
	rest, err := asn1.Unmarshal(request.RawTBSCertificateRequest, &info)
	if err != nil || len(rest) != 0 {
		return false
	}
	extensionRequestOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	extensionRequestCount := 0
	for _, raw := range info.RawAttributes {
		var sequence asn1.RawValue
		sequenceRest, sequenceErr := asn1.Unmarshal(raw.FullBytes, &sequence)
		if sequenceErr != nil || len(sequenceRest) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence {
			continue
		}
		var id asn1.ObjectIdentifier
		if _, idErr := asn1.Unmarshal(sequence.Bytes, &id); idErr != nil || !id.Equal(extensionRequestOID) {
			continue
		}
		var attribute struct {
			ID     asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		}
		attributeRest, attributeErr := asn1.Unmarshal(raw.FullBytes, &attribute)
		if attributeErr != nil || len(attributeRest) != 0 {
			return false
		}
		extensionRequestCount++
		if extensionRequestCount > 1 || len(attribute.Values) != 1 {
			return false
		}
	}
	return true
}

func supportedCSRIssueSANOracle(value []byte) bool {
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(value, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return false
	}
	generalNames := sequence.Bytes
	if len(generalNames) == 0 {
		return false
	}
	for len(generalNames) > 0 {
		var name asn1.RawValue
		generalNames, err = asn1.Unmarshal(generalNames, &name)
		if err != nil || name.Class != asn1.ClassContextSpecific || name.IsCompound {
			return false
		}
		switch name.Tag {
		case 2:
			for _, character := range name.Bytes {
				if character > 0x7f {
					return false
				}
			}
		case 7:
			if len(name.Bytes) != net.IPv4len && len(name.Bytes) != net.IPv6len {
				return false
			}
		default:
			return false
		}
	}
	return true
}
