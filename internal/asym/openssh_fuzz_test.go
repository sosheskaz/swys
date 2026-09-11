package asym

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

const testOpenSSHMagic = "openssh-key-v1\x00"

type testOpenSSHEnvelope struct { //nolint:govet // Field order is the SSH wire format.
	Cipher, KDF, Options string
	Count                uint32
	Public, Private      []byte
	Rest                 []byte `ssh:"rest"`
}

type testOpenSSHPrivateHeader struct { //nolint:govet // Field order is the SSH wire format.
	Check1, Check2 uint32
	Type           string
	Rest           []byte `ssh:"rest"`
}

type testOpenSSHEd25519 struct {
	Public, Private []byte
	Comment         string
	Padding         []byte `ssh:"rest"`
}

func newOpenSSHFuzzEnvelope(tb testing.TB) testOpenSSHEnvelope {
	tb.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "generated fuzz fixture")
	if err != nil {
		tb.Fatal(err)
	}
	var envelope testOpenSSHEnvelope
	if err := ssh.Unmarshal(block.Bytes[len(testOpenSSHMagic):], &envelope); err != nil {
		tb.Fatal(err)
	}
	return envelope
}

func encodeOpenSSHFuzzEnvelope(envelope *testOpenSSHEnvelope) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: append([]byte(testOpenSSHMagic), ssh.Marshal(envelope)...)})
}

func mutateOpenSSHEd25519(tb testing.TB, envelope *testOpenSSHEnvelope, mutate func(*testOpenSSHEd25519)) {
	tb.Helper()
	var header testOpenSSHPrivateHeader
	if err := ssh.Unmarshal(envelope.Private, &header); err != nil {
		tb.Fatal(err)
	}
	var key testOpenSSHEd25519
	if err := ssh.Unmarshal(header.Rest, &key); err != nil {
		tb.Fatal(err)
	}
	mutate(&key)
	header.Rest = ssh.Marshal(key)
	envelope.Private = ssh.Marshal(header)
}

func TestParseOpenSSHRejectsInconsistentPrivateKeyFields(t *testing.T) {
	t.Parallel()
	mutations := map[string]func(*testing.T, *testOpenSSHEnvelope){
		"missing outer public key":   func(_ *testing.T, e *testOpenSSHEnvelope) { e.Public = nil },
		"malformed outer public key": func(_ *testing.T, e *testOpenSSHEnvelope) { e.Public = []byte("invalid") },
		"different outer public key": func(t *testing.T, e *testOpenSSHEnvelope) {
			t.Helper()
			e.Public = newOpenSSHFuzzEnvelope(t).Public
		},
		"different inner public key": func(t *testing.T, e *testOpenSSHEnvelope) {
			t.Helper()

			mutateOpenSSHEd25519(t, e, func(k *testOpenSSHEd25519) { k.Public = bytes.Clone(k.Public); k.Public[0] ^= 1 })
		},
		"inconsistent private public suffix": func(t *testing.T, e *testOpenSSHEnvelope) {
			t.Helper()

			mutateOpenSSHEd25519(t, e, func(k *testOpenSSHEd25519) { k.Private = bytes.Clone(k.Private); k.Private[ed25519.SeedSize] ^= 1 })
		},
		"inconsistent private seed": func(t *testing.T, e *testOpenSSHEnvelope) {
			t.Helper()

			mutateOpenSSHEd25519(t, e, func(k *testOpenSSHEd25519) { k.Private = bytes.Clone(k.Private); k.Private[0] ^= 1 })
		},
		"unaligned private block": func(t *testing.T, e *testOpenSSHEnvelope) {
			t.Helper()

			mutateOpenSSHEd25519(t, e, func(k *testOpenSSHEd25519) { k.Padding = append(bytes.Clone(k.Padding), byte(len(k.Padding)+1)) })
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			envelope := newOpenSSHFuzzEnvelope(t)
			mutate(t, &envelope)
			if _, err := ParseKey(encodeOpenSSHFuzzEnvelope(&envelope)); !errors.Is(err, ErrMalformedKey) {
				t.Fatalf("error = %v, want malformed key", err)
			}
		})
	}
}

func FuzzOpenSSHPrivateEnvelope(f *testing.F) {
	envelope := newOpenSSHFuzzEnvelope(f)
	f.Add(append([]byte(testOpenSSHMagic), ssh.Marshal(envelope)...))
	f.Add([]byte(testOpenSSHMagic))
	f.Add([]byte{})
	for _, algorithm := range []KeyAlgorithm{KeyAlgorithmRSA2048, KeyAlgorithmECDSAP256, KeyAlgorithmECDSAP384} {
		key, err := GeneratePrivateKey(algorithm)
		if err != nil {
			f.Fatal(err)
		}
		block, err := ssh.MarshalPrivateKey(key, "generated fuzz fixture")
		if err != nil {
			f.Fatal(err)
		}
		f.Add(block.Bytes)
	}
	key521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	block521, err := ssh.MarshalPrivateKey(key521, "generated fuzz fixture")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(block521.Bytes)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		key, err := ParseKey(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: data}))
		if err != nil {
			return
		}
		if !key.IsPrivate() {
			t.Fatal("private envelope produced public key")
		}
		assertOpenSSHFuzzRoundTrip(t, key)
		if _, err := ParseKey(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: append(bytes.Clone(data), 0)})); err == nil {
			t.Fatal("accepted trailing envelope byte")
		}
	})
}

func TestParseOpenSSHRejectsMismatchedECDSAType(t *testing.T) {
	t.Parallel()
	key, err := GeneratePrivateKey(KeyAlgorithmECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "generated fixture")
	if err != nil {
		t.Fatal(err)
	}
	var envelope testOpenSSHEnvelope
	if err := ssh.Unmarshal(block.Bytes[len(testOpenSSHMagic):], &envelope); err != nil {
		t.Fatal(err)
	}
	var header testOpenSSHPrivateHeader
	if err := ssh.Unmarshal(envelope.Private, &header); err != nil {
		t.Fatal(err)
	}
	header.Type = ssh.KeyAlgoECDSA384
	envelope.Private = ssh.Marshal(header)
	if _, err := ParseKey(encodeOpenSSHFuzzEnvelope(&envelope)); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("error = %v, want malformed key", err)
	}
}

func FuzzOpenSSHAuthorizedKey(f *testing.F) {
	envelope := newOpenSSHFuzzEnvelope(f)
	public, err := ssh.ParsePublicKey(envelope.Public)
	if err != nil {
		f.Fatal(err)
	}
	line := ssh.MarshalAuthorizedKey(public)
	f.Add(line)
	f.Add(append([]byte("# comment\nrestrict,command=\"echo test\" "), line...))
	f.Add([]byte("ssh-ed25519 invalid"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		key, err := parseOpenSSHPublicKey(data)
		if err != nil {
			return
		}
		if key.IsPrivate() {
			t.Fatal("authorized_keys produced private key")
		}
		assertOpenSSHFuzzRoundTrip(t, key)
		canonical, err := key.Marshal(KeyFormatOpenSSH)
		if err != nil {
			t.Fatal(err)
		}
		multiple := append(append(bytes.Clone(data), '\n'), canonical...)
		if _, err := ParseKey(multiple); err == nil {
			t.Fatal("accepted multiple public entries")
		}
		if _, err := ParseKey(append([]byte("invalid non-comment line\n"), data...)); err == nil {
			t.Fatal("ignored malformed line before public key")
		}
	})
}

func assertOpenSSHFuzzRoundTrip(t *testing.T, key *Key) {
	t.Helper()
	before, err := key.Info()
	if err != nil {
		t.Fatal(err)
	}
	format := KeyFormatPKIXDER
	if key.IsPrivate() {
		format = KeyFormatPKCS8DER
	}
	canonical, err := key.Marshal(format)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseKey(canonical)
	if err != nil {
		t.Fatal(err)
	}
	after, err := parsed.Info()
	if err != nil {
		t.Fatal(err)
	}
	if *before != *after {
		t.Fatal("key identity changed during canonical round trip")
	}
}
