package crypter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"
	"testing/iotest"

	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
)

const testStreamChunkSize uint32 = 64

func TestAESStreamingBoundaries(t *testing.T) {
	t.Parallel()

	for _, keySize := range []int{16, 32} {
		t.Run(fmt.Sprintf("AES_%d", keySize*8), func(t *testing.T) {
			t.Parallel()
			firstPlaintext := int(testStreamChunkSize) - (1 + keySize + 7)
			for _, size := range []int{
				0,
				1,
				firstPlaintext - 1,
				firstPlaintext,
				firstPlaintext + 1,
				firstPlaintext + int(testStreamChunkSize) - 1,
				firstPlaintext + int(testStreamChunkSize),
				firstPlaintext + int(testStreamChunkSize) + 1,
			} {
				t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
					plaintext := patternedBytes(size)
					wire := encryptStream(t, bytes.Repeat([]byte{byte(keySize)}, keySize), plaintext, []byte("boundary"), testStreamChunkSize)
					opened, err := decryptStream(bytes.Repeat([]byte{byte(keySize)}, keySize), wire, []byte("boundary"))
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(opened, plaintext) {
						t.Fatalf("round trip changed %d-byte plaintext", size)
					}
					segments := 1
					if size > firstPlaintext {
						segments += (size - firstPlaintext + int(testStreamChunkSize) - 1) / int(testStreamChunkSize)
					}
					wantWireLength := aesStreamHeaderSize + 1 + keySize + 7 + size + 16*segments
					if len(wire) != wantWireLength {
						t.Fatalf("wire length = %d, want %d for %d segments", len(wire), wantWireLength, segments)
					}
				})
			}
		})
	}
}

func TestAESStreamingDirectTinkInteroperabilityAndAAD(t *testing.T) {
	t.Parallel()

	for _, keySize := range []int{16, 32} {
		key := bytes.Repeat([]byte{byte(0x40 + keySize)}, keySize)
		plaintext := patternedBytes(211)
		aad := []byte{0, 0xff, 'N', 'P', 'C', 0}
		wire := encryptStream(t, key, plaintext, aad, 97)
		header := bytes.Clone(wire[:aesStreamHeaderSize])
		primitive, err := subtle.NewAESGCMHKDF(key, "SHA256", keySize, 97+16, 0)
		if err != nil {
			t.Fatal(err)
		}
		expectedAAD := independentStreamAAD(header, aad)
		reader, err := primitive.NewDecryptingReader(bytes.NewReader(wire[aesStreamHeaderSize:]), expectedAAD)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Fatal("Tink did not open the NPC stream")
		}

		var tink bytes.Buffer
		writer, err := primitive.NewEncryptingWriter(&tink, expectedAAD)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(plaintext); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		tinkWire := append(bytes.Clone(header), tink.Bytes()...)
		opened, err = decryptStream(key, tinkWire, aad)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Fatal("NPC did not open the direct Tink stream")
		}

		for _, wrongAAD := range [][]byte{nil, []byte("different"), append(bytes.Clone(aad), 0)} {
			wrongOutput, wrongErr := decryptStream(key, wire, wrongAAD)
			if wrongErr == nil || len(wrongOutput) != 0 {
				t.Fatalf(
					"wrong AAD %x = %d plaintext bytes, error %v; want no plaintext and failure",
					wrongAAD,
					len(wrongOutput),
					wrongErr,
				)
			}
		}

		wrongKey := bytes.Repeat([]byte{byte(0x20 + keySize)}, keySize)
		wrongOutput, wrongErr := decryptStream(wrongKey, wire, aad)
		if wrongErr == nil || len(wrongOutput) != 0 {
			t.Fatalf(
				"same-length wrong AES-%d key = %d plaintext bytes, error %v; want no plaintext and failure",
				keySize*8,
				len(wrongOutput),
				wrongErr,
			)
		}
	}
}

func TestAESStreamingRejectsUntrustedEnvelopeBeforeBodyRead(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x44}, 32)
	valid := encryptStream(t, key, []byte("payload"), nil, testStreamChunkSize)
	tests := []struct {
		mutate func([]byte)
		name   string
	}{
		{name: "magic", mutate: func(header []byte) { header[0] ^= 1 }},
		{name: "version", mutate: func(header []byte) { header[8]++ }},
		{name: "suite", mutate: func(header []byte) { header[9] = 1 }},
		{name: "length", mutate: func(header []byte) { binary.BigEndian.PutUint16(header[10:12], 17) }},
		{name: "chunk below minimum", mutate: func(header []byte) { binary.BigEndian.PutUint32(header[12:16], MinAESChunkSize-1) }},
		{name: "chunk above maximum", mutate: func(header []byte) { binary.BigEndian.PutUint32(header[12:16], MaxAESChunkSize+1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			header := bytes.Clone(valid[:aesStreamHeaderSize])
			test.mutate(header)
			reader := &stepReader{steps: []readStep{{data: header}, {err: errLateReader}}}
			stream, err := NewAESStreamingCrypter(key)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			err = stream.Decrypt(reader, &output, nil)
			if err == nil || output.Len() != 0 {
				t.Fatalf("invalid header = %d plaintext bytes, error %v", output.Len(), err)
			}
			if errors.Is(err, errLateReader) || reader.next != 1 {
				t.Fatalf("invalid header read body: next step %d, error %v", reader.next, err)
			}
		})
	}
}

func TestAESStreamingAuthenticatesSegmentsBeforeRelease(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x55}, 32)
	firstPlaintext := int(testStreamChunkSize) - 40
	plaintext := patternedBytes(firstPlaintext + int(testStreamChunkSize) + 20)
	wire := encryptStream(t, key, plaintext, []byte("segments"), testStreamChunkSize)
	const (
		tinkHeaderStart  = aesStreamHeaderSize
		tinkHeaderEnd    = tinkHeaderStart + 40
		firstSegmentEnd  = tinkHeaderEnd + 40
		secondSegmentEnd = firstSegmentEnd + 80
	)
	first := bytes.Clone(wire[tinkHeaderEnd:firstSegmentEnd])
	second := bytes.Clone(wire[firstSegmentEnd:secondSegmentEnd])
	final := bytes.Clone(wire[secondSegmentEnd:])
	prefix := bytes.Clone(wire[:tinkHeaderEnd])
	other := encryptStream(t, key, bytes.Repeat([]byte{0xa5}, len(plaintext)), []byte("segments"), testStreamChunkSize)
	otherSecond := bytes.Clone(other[firstSegmentEnd:secondSegmentEnd])

	tests := []struct {
		name       string
		wire       []byte
		wantPrefix int
	}{
		{name: "mutated first", wire: mutateStreamByte(wire, tinkHeaderEnd), wantPrefix: 0},
		{name: "mutated second", wire: mutateStreamByte(wire, firstSegmentEnd), wantPrefix: firstPlaintext},
		{name: "mutated final", wire: mutateStreamByte(wire, secondSegmentEnd), wantPrefix: firstPlaintext + int(testStreamChunkSize)},
		{name: "reordered", wire: joinStream(prefix, second, first, final), wantPrefix: 0},
		{name: "duplicated", wire: joinStream(prefix, first, second, second, final), wantPrefix: firstPlaintext + int(testStreamChunkSize)},
		{name: "spliced", wire: joinStream(prefix, first, otherSecond, final), wantPrefix: firstPlaintext},
		{name: "truncated", wire: bytes.Clone(wire[:len(wire)-1]), wantPrefix: firstPlaintext + int(testStreamChunkSize)},
		{name: "appended", wire: append(bytes.Clone(wire), 0), wantPrefix: firstPlaintext + int(testStreamChunkSize)},
		{name: "concatenated", wire: append(bytes.Clone(wire), wire...), wantPrefix: firstPlaintext + int(testStreamChunkSize)},
		{name: "missing final", wire: bytes.Clone(wire[:secondSegmentEnd]), wantPrefix: firstPlaintext},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			opened, err := decryptStream(key, test.wire, []byte("segments"))
			if err == nil {
				t.Fatal("corrupted stream decrypted successfully")
			}
			if !bytes.Equal(opened, plaintext[:test.wantPrefix]) {
				t.Fatalf("released plaintext = %d bytes, want exact %d-byte authenticated prefix", len(opened), test.wantPrefix)
			}
		})
	}
}

func TestAESStreamingIOFailuresAndOwnership(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x66}, 32)
	stream, err := NewAESStreamingCrypter(key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := patternedBytes(200)
	wire := encryptStream(t, key, plaintext, nil, testStreamChunkSize)

	t.Run("source error does not finalize", func(t *testing.T) {
		t.Parallel()
		reader := &stepReader{steps: []readStep{{data: patternedBytes(200), err: errTestRead}}}
		var partial bytes.Buffer
		err := stream.Encrypt(reader, &partial, nil, testStreamChunkSize)
		assertErrorIs(t, err, errTestRead)
		opened, decryptErr := decryptStream(key, partial.Bytes(), nil)
		if decryptErr == nil || bytes.Equal(opened, patternedBytes(200)) {
			t.Fatalf("source failure produced a successful complete stream: %d bytes, %v", len(opened), decryptErr)
		}
	})

	t.Run("short ciphertext write", func(t *testing.T) {
		t.Parallel()
		writer := &shortOnCallWriter{shortCall: 2}
		err := stream.Encrypt(bytes.NewReader(plaintext), writer, nil, testStreamChunkSize)
		assertErrorIs(t, err, io.ErrShortWrite)
	})

	t.Run("ciphertext write error", func(t *testing.T) {
		t.Parallel()
		writer := &countingWriter{err: errTestWrite}
		err := stream.Encrypt(bytes.NewReader(plaintext), writer, nil, testStreamChunkSize)
		assertErrorIs(t, err, errTestWrite)
	})

	t.Run("short plaintext write", func(t *testing.T) {
		t.Parallel()
		writer := &shortOnCallWriter{shortCall: 1}
		err := stream.Decrypt(bytes.NewReader(wire), writer, nil)
		assertErrorIs(t, err, io.ErrShortWrite)
	})

	t.Run("plaintext write error", func(t *testing.T) {
		t.Parallel()
		writer := &countingWriter{err: errTestWrite}
		err := stream.Decrypt(bytes.NewReader(wire), writer, nil)
		assertErrorIs(t, err, errTestWrite)
	})

	t.Run("Tink header read error identity", func(t *testing.T) {
		t.Parallel()
		reader := &stepReader{steps: []readStep{{data: wire[:aesStreamHeaderSize]}, {data: wire[aesStreamHeaderSize : aesStreamHeaderSize+3], err: errTestRead}}}
		var output bytes.Buffer
		err := stream.Decrypt(reader, &output, nil)
		assertErrorIs(t, err, errTestRead)
		assertNoWrites(t, &countingWriter{data: output.Bytes()})
	})

	t.Run("fragmented ciphertext", func(t *testing.T) {
		t.Parallel()
		var output bytes.Buffer
		err := stream.Decrypt(iotest.OneByteReader(bytes.NewReader(wire)), &output, nil)
		if err != nil || !bytes.Equal(output.Bytes(), plaintext) {
			t.Fatalf("fragmented decrypt = %d bytes, error %v", output.Len(), err)
		}
	})

	t.Run("cancellation error identity", func(t *testing.T) {
		t.Parallel()
		reader := &stepReader{steps: []readStep{{data: patternedBytes(65), err: context.Canceled}}}
		var output bytes.Buffer
		err := stream.Encrypt(reader, &output, nil, testStreamChunkSize)
		assertErrorIs(t, err, context.Canceled)
	})

	t.Run("borrowed streams remain open", func(t *testing.T) {
		t.Parallel()
		input := &closeTrackingReader{Reader: bytes.NewReader(plaintext)}
		ciphertext := &closeTrackingWriter{}
		if err := stream.Encrypt(input, ciphertext, nil, testStreamChunkSize); err != nil {
			t.Fatal(err)
		}
		if input.closed || ciphertext.closed {
			t.Fatal("Encrypt closed a caller-owned stream")
		}
		cipherInput := &closeTrackingReader{Reader: bytes.NewReader(ciphertext.Bytes())}
		opened := &closeTrackingWriter{}
		if err := stream.Decrypt(cipherInput, opened, nil); err != nil {
			t.Fatal(err)
		}
		if cipherInput.closed || opened.closed {
			t.Fatal("Decrypt closed a caller-owned stream")
		}
	})
}

func encryptStream(tb testing.TB, key, plaintext, aad []byte, chunkSize uint32) []byte {
	tb.Helper()
	stream, err := NewAESStreamingCrypter(key)
	if err != nil {
		tb.Fatal(err)
	}
	var wire bytes.Buffer
	if err := stream.Encrypt(bytes.NewReader(plaintext), &wire, aad, chunkSize); err != nil {
		tb.Fatal(err)
	}
	return bytes.Clone(wire.Bytes())
}

func decryptStream(key, wire, aad []byte) ([]byte, error) {
	stream, err := NewAESStreamingCrypter(key)
	if err != nil {
		return nil, err
	}
	var plaintext bytes.Buffer
	err = stream.Decrypt(bytes.NewReader(wire), &plaintext, aad)
	return bytes.Clone(plaintext.Bytes()), err
}

func mutateStreamByte(wire []byte, index int) []byte {
	mutated := bytes.Clone(wire)
	mutated[index] ^= 1
	return mutated
}

func joinStream(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

func independentStreamAAD(header, aad []byte) []byte {
	expected := make([]byte, 0, len("npc/aes-gcm-stream/v1\x00")+len(header)+len(aad))
	expected = append(expected, []byte("npc/aes-gcm-stream/v1\x00")...)
	expected = append(expected, header...)
	return append(expected, aad...)
}

type shortOnCallWriter struct {
	calls     int
	shortCall int
}

func (w *shortOnCallWriter) Write(data []byte) (int, error) {
	w.calls++
	if w.calls == w.shortCall && len(data) > 0 {
		return len(data) - 1, nil
	}
	return len(data), nil
}

type closeTrackingReader struct {
	io.Reader
	closed bool
}

func (r *closeTrackingReader) Close() error {
	r.closed = true
	return nil
}

type closeTrackingWriter struct {
	bytes.Buffer
	closed bool
}

func (w *closeTrackingWriter) Close() error {
	w.closed = true
	return nil
}
