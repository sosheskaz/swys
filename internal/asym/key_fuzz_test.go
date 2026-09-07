package asym

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func FuzzParseKey(f *testing.F) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	for _, material := range []any{private, ec} {
		key, keyErr := NewKey(material)
		if keyErr != nil {
			f.Fatal(keyErr)
		}
		for _, format := range []KeyFormat{KeyFormatPKCS8DER, KeyFormatPKCS8PEM, KeyFormatPKIXDER, KeyFormatPKIXPEM} {
			data, marshalErr := key.Marshal(format)
			if marshalErr != nil {
				f.Fatal(marshalErr)
			}
			f.Add(data)
		}
	}
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\n!\n-----END PRIVATE KEY-----"))
	f.Add([]byte{0x30, 0x80})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		parsed, parseErr := ParseKey(data)
		if parseErr != nil {
			return
		}
		before, infoErr := parsed.Info()
		if infoErr != nil {
			t.Fatal(infoErr)
		}
		format := KeyFormatPKIXDER
		if parsed.IsPrivate() {
			format = KeyFormatPKCS8DER
		}
		canonical, marshalErr := parsed.Marshal(format)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		roundtrip, roundtripErr := ParseKey(canonical)
		if roundtripErr != nil {
			t.Fatal(roundtripErr)
		}
		after, infoErr := roundtrip.Info()
		if infoErr != nil {
			t.Fatal(infoErr)
		}
		if *before != *after {
			t.Fatalf("key identity changed: before %+v, after %+v", before, after)
		}
	})
}
