package crypter

import (
	"bytes"
	"encoding/binary"
	"testing"
	"testing/iotest"
)

func FuzzAESStreamingFragmentedRoundTrip(f *testing.F) {
	f.Add([]byte("payload"), []byte("aad"), uint16(0), false)
	f.Add(patternedBytes(211), []byte{0, 0xff}, uint16(33), true)
	f.Add([]byte{}, []byte{}, uint16(192), false)
	f.Fuzz(func(t *testing.T, plaintext, aad []byte, chunkSelector uint16, aes256 bool) {
		if len(plaintext) > 4096 || len(aad) > 256 {
			t.Skip()
		}
		keySize := 16
		if aes256 {
			keySize = 32
		}
		chunkSize := uint32(chunkSelector%193) + MinAESChunkSize
		key := bytes.Repeat([]byte{byte(chunkSelector)}, keySize)
		wire := encryptStream(t, key, plaintext, aad, chunkSize)
		stream, err := NewAESStreamingCrypter(key)
		if err != nil {
			t.Fatal(err)
		}
		var opened bytes.Buffer
		if err := stream.Decrypt(iotest.OneByteReader(bytes.NewReader(wire)), &opened, aad); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(opened.Bytes(), plaintext) {
			t.Fatal("fragmented fuzz round trip changed plaintext")
		}
	})
}

func FuzzAESStreamingBoundedHeaderAndCorruption(f *testing.F) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	valid := encryptStream(f, key, patternedBytes(211), []byte("aad"), 97)
	f.Add(valid, []byte("aad"))
	f.Add(mutateStreamByte(valid, aesStreamHeaderSize+40), []byte("aad"))
	f.Add(valid[:aesStreamHeaderSize-1], []byte("aad"))
	f.Add(append(bytes.Clone(valid), 0), []byte("aad"))
	f.Fuzz(func(t *testing.T, wire, aad []byte) {
		if len(wire) > 8192 || len(aad) > 256 {
			t.Skip()
		}
		if len(wire) >= aesStreamHeaderSize {
			chunkSize := binary.BigEndian.Uint32(wire[12:16])
			if chunkSize >= MinAESChunkSize && chunkSize <= MaxAESChunkSize && chunkSize > 4096 {
				t.Skip()
			}
		}
		stream, err := NewAESStreamingCrypter(key)
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		decryptErr := stream.Decrypt(iotest.OneByteReader(bytes.NewReader(wire)), &output, aad)
		if decryptErr != nil {
			return
		}
		if output.Len() > len(wire) {
			t.Fatalf("decrypted %d bytes from %d wire bytes", output.Len(), len(wire))
		}
	})
}

func FuzzAESStreamingMutationAuthenticatedPrefix(f *testing.F) {
	key := bytes.Repeat([]byte{0x6b}, 32)
	const chunkSize uint32 = 64
	const firstPlaintext = 24
	plaintext := patternedBytes(firstPlaintext + int(chunkSize) + 20)
	valid := encryptStream(f, key, plaintext, []byte("mutation aad"), chunkSize)
	for _, seed := range []struct {
		position uint16
		bit      uint8
	}{
		{position: 0, bit: 0},
		{position: 39, bit: 7},
		{position: 40, bit: 3},
		{position: 80, bit: 5},
		{position: 160, bit: 1},
	} {
		f.Add(seed.position, seed.bit)
	}
	f.Fuzz(func(t *testing.T, position uint16, bit uint8) {
		const (
			tinkHeaderEnd    = aesStreamHeaderSize + 40
			firstSegmentEnd  = tinkHeaderEnd + 40
			secondSegmentEnd = firstSegmentEnd + 80
		)
		index := aesStreamHeaderSize + int(position)%(len(valid)-aesStreamHeaderSize)
		mutated := bytes.Clone(valid)
		mutated[index] ^= 1 << (bit % 8)
		wantPrefix := 0
		switch {
		case index >= secondSegmentEnd:
			wantPrefix = firstPlaintext + int(chunkSize)
		case index >= firstSegmentEnd:
			wantPrefix = firstPlaintext
		}
		opened, err := decryptStream(key, mutated, []byte("mutation aad"))
		if err == nil {
			t.Fatal("mutated stream decrypted successfully")
		}
		if !bytes.Equal(opened, plaintext[:wantPrefix]) {
			t.Fatalf(
				"mutation at byte %d released %d bytes, want exact %d-byte authenticated prefix",
				index,
				len(opened),
				wantPrefix,
			)
		}
	})
}
