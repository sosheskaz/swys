package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
)

func FuzzParsePEMCertificates(f *testing.F) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		f.Fatal(err)
	}
	seed := pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: der})
	f.Add(seed)
	template.SerialNumber = big.NewInt(2)
	secondDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		f.Fatal(err)
	}
	second := pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: secondDER})
	f.Add(append(bytes.Clone(seed), second...))
	f.Add(append(bytes.Clone(second), seed...))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16384 {
			t.Skip()
		}
		certs, parseErr := parsePEMCertificates(data)
		if parseErr != nil {
			return
		}
		if len(certs) == 0 {
			t.Fatal("successful parse returned no certificates")
		}
		var canonical bytes.Buffer
		remaining := data
		for _, cert := range certs {
			block, rest := pem.Decode(remaining)
			if block == nil || !bytes.Equal(block.Bytes, cert.Raw) {
				t.Fatal("parsed certificate differs from source order or DER")
			}
			remaining = rest
			if encodeErr := pem.Encode(&canonical, &pem.Block{Type: certificatePEMType, Bytes: cert.Raw}); encodeErr != nil {
				t.Fatal(encodeErr)
			}
		}
		if block, _ := pem.Decode(remaining); block != nil {
			t.Fatal("successful parse discarded certificates")
		}
		roundtrip, roundtripErr := parsePEMCertificates(canonical.Bytes())
		if roundtripErr != nil {
			t.Fatal(roundtripErr)
		}
		if len(roundtrip) != len(certs) {
			t.Fatal("certificate count changed")
		}
		for index, cert := range certs {
			if !bytes.Equal(cert.Raw, roundtrip[index].Raw) {
				t.Fatal("certificate bytes or order changed")
			}
		}
	})
}
