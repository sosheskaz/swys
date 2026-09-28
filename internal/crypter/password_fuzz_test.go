package crypter

import (
	"bytes"
	"testing"
)

// FuzzOpenPGPPasswordPreflight covers wrapper framing and KDF cost checks.
// It never calls Open, so no fuzzed cost is ever derived.
func FuzzOpenPGPPasswordPreflight(f *testing.F) {
	wrapper := func() []byte {
		prepared, err := PreparePasswordOpenPGP(testPassword, cheapArgon2)
		if err != nil {
			f.Fatal(err)
		}
		return prepared.wrapper
	}()
	var seipd bytes.Buffer
	if err := EncryptOpenPGP(testSessionKey, 64, bytes.NewReader([]byte("seed")), &seipd); err != nil {
		f.Fatal(err)
	}
	f.Add(append(bytes.Clone(wrapper), seipd.Bytes()...))
	f.Add(append(withCosts(wrapper, 10, 16, 18), seipd.Bytes()...))
	f.Add(append(bytes.Repeat(withCosts(wrapper, 5, 1, 18), 3), seipd.Bytes()...))
	f.Add([]byte{0xc3, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x8f, 0x06})

	f.Fuzz(func(t *testing.T, wire []byte) {
		counted := &countingReader{reader: bytes.NewReader(wire)}
		message, err := PrepareOpenPGPPassword(counted)
		if counted.read > 4096 {
			t.Fatalf("preflight read %d bytes", counted.read)
		}
		if err != nil {
			return
		}
		if len(message.wrappers) == 0 || len(message.wrappers) > maxPasswordWrappers {
			t.Fatalf("accepted %d wrappers", len(message.wrappers))
		}
	})
}
