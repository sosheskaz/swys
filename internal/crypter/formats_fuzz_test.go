package crypter

import (
	"bytes"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
)

func FuzzAESWireDecryptBounded(f *testing.F) {
	key := bytes.Repeat([]byte{0x42}, 32)
	primitive, err := subtle.NewAESGCMHKDF(key, "SHA256", 32, 64, 0)
	if err != nil {
		f.Fatal(err)
	}
	var pgpWire, tinkWire bytes.Buffer
	if err := EncryptOpenPGP(key, 64, bytes.NewReader([]byte("seed")), &pgpWire); err != nil {
		f.Fatal(err)
	}
	if err := EncryptTink(primitive, bytes.NewReader([]byte("seed")), &tinkWire, nil); err != nil {
		f.Fatal(err)
	}
	f.Add(byte(0), pgpWire.Bytes())
	f.Add(byte(1), tinkWire.Bytes())
	f.Add(byte(0), []byte{0xd2, 0xff})
	f.Add(byte(2), []byte{0xcb, 0x06, 'b', 0, 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, format byte, wire []byte) {
		if len(wire) > 4096 {
			t.Skip()
		}
		if format%3 == 2 {
			var wrapped bytes.Buffer
			writer, err := packet.SerializeSymmetricallyEncrypted(&wrapped, 0, true,
				packet.CipherSuite{Cipher: packet.CipherAES256, Mode: packet.AEADModeGCM},
				key, &packet.Config{AEADConfig: &packet.AEADConfig{ChunkSize: 64}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(wire); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			wire = wrapped.Bytes()
		}
		if format%3 != 1 {
			reader, err := PrepareOpenPGP(key, bytes.NewReader(wire))
			if err == nil {
				if err := reader.CopyTo(&limitedAESWriter{remaining: 1 << 16}); err != nil {
					return
				}
			}
			return
		}
		reader, err := primitive.NewDecryptingReader(bytes.NewReader(wire), nil)
		if err == nil {
			if _, err := io.Copy(io.Discard, io.LimitReader(reader, 1<<16)); err != nil {
				return
			}
		}
	})
}

type limitedAESWriter struct{ remaining int }

func (w *limitedAESWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, io.ErrShortWrite
	}
	w.remaining -= len(p)
	return len(p), nil
}
