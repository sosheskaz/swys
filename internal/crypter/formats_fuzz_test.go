package crypter

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"testing/cryptotest"

	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
)

const (
	aesFuzzMaxPlaintext = 2 << 10
	aesFuzzMaxExtra     = 4 << 10
	// aesFuzzTinkFirstRead is the Tink read that aes decrypt authenticates
	// before it opens output.
	aesFuzzTinkFirstRead = 512
	// openPGPSEIPDv2Header counts the version, cipher, mode, chunk-size, and
	// salt octets before the first AEAD chunk.
	openPGPSEIPDv2Header = 4 + 32
	aesFuzzTagSize       = 16
)

const (
	aesTamperNone = iota
	aesTamperTruncate
	aesTamperAppend
	aesTamperFlip
	aesTamperSwap
	aesTamperReplace
	aesTamperKinds
)

// Whether a tampered stream must decrypt, must fail, or may do either.
const (
	aesExpectSuccess = iota
	aesExpectFailure
	aesExpectEither
)

var errAESFuzzOutputLimit = errors.New("decrypted output exceeds the plaintext")

// FuzzAESWireDecryptBounded encrypts a generated plaintext, applies at most one
// generated tampering, and decrypts through the steps aes decrypt uses. Success
// must reproduce the plaintext exactly, and failure may leave only a plaintext
// prefix. The untampered stream must decrypt; truncation, trailing bytes, and
// changes to authenticated bytes must fail; errors must not carry the key.
// TestOpenPGPReleasesOnlyAuthenticatedChunks and cmd's
// TestAESTinkRejectsUnauthenticatedSegments pin the chunk at which a failure
// stops releasing plaintext; this target checks the prefix across layouts.
func FuzzAESWireDecryptBounded(f *testing.F) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xa0 + i)
	}
	plaintext := make([]byte, 300)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	large := bytes.Repeat(plaintext, 5)
	for _, tink := range []bool{false, true} {
		// Seeds locate structure from lengths, which do not depend on randomness.
		stream := newAESFuzzStream(f, key, tink, 0, plaintext)
		last := uint16(len(stream.wire) - 1)
		f.Add(tink, byte(0), []byte{}, byte(aesTamperNone), uint16(0), []byte{})
		f.Add(tink, byte(0), plaintext, byte(aesTamperNone), uint16(0), []byte{})
		f.Add(tink, byte(0), plaintext, byte(aesTamperTruncate), last, []byte{})
		f.Add(tink, byte(0), plaintext, byte(aesTamperTruncate), stream.segmentStart(2), []byte{})
		f.Add(tink, byte(0), plaintext, byte(aesTamperAppend), uint16(0), []byte{0})
		f.Add(tink, byte(0), plaintext, byte(aesTamperFlip), last, []byte{1})
		f.Add(tink, byte(0), plaintext, byte(aesTamperFlip), stream.segmentStart(1)+5, []byte{1})
		f.Add(tink, byte(0), plaintext, byte(aesTamperFlip), uint16(stream.authenticated[1]), []byte{1})
		f.Add(tink, byte(0), plaintext, byte(aesTamperSwap), uint16(0), []byte{})
		f.Add(tink, byte(200), large, byte(aesTamperNone), uint16(0), []byte{})
		f.Add(tink, byte(0), large, byte(aesTamperFlip), uint16(1), []byte{1})
	}
	f.Add(false, byte(0), plaintext, byte(aesTamperReplace), uint16(0), []byte{0xd2, 0xff})
	f.Add(true, byte(0), plaintext, byte(aesTamperReplace), uint16(0), []byte{40})

	f.Fuzz(func(t *testing.T, tink bool, chunkSel byte, plaintext []byte, kind byte, at uint16, extra []byte) {
		if len(plaintext) > aesFuzzMaxPlaintext || len(extra) > aesFuzzMaxExtra {
			t.Skip()
		}
		// A fixed random stream makes each input's salt, and so the bytes a
		// tampering changes, reproducible.
		cryptotest.SetGlobalRandom(t, 1)
		stream := newAESFuzzStream(t, key, tink, chunkSel, plaintext)
		tampered, expect := stream.tamper(kind, at, extra)
		if bytes.Equal(tampered, stream.wire) {
			expect = aesExpectSuccess
		}
		output := &aesFuzzOutput{limit: len(plaintext)}
		err := stream.decrypt(key, tampered, output)
		got := output.data
		desc := describeAESFuzzError(err, key)
		label := fmt.Sprintf("tink=%t chunk selector %d, tamper %d at %d", tink, chunkSel, kind%aesTamperKinds, at)

		if output.exceeded {
			t.Errorf("%s: decryption wrote past the %d-byte plaintext", label, len(plaintext))
		}
		if err == nil && !bytes.Equal(plaintext, got) {
			t.Errorf("%s: successful decryption returned %d bytes that differ from the %d-byte plaintext", label, len(got), len(plaintext))
		}
		if err != nil && !bytes.HasPrefix(plaintext, got) {
			t.Errorf("%s: failed decryption released %d bytes that are not a plaintext prefix: %s", label, len(got), desc)
		}
		switch {
		case expect == aesExpectSuccess && err != nil:
			t.Errorf("%s: untampered stream failed: %s", label, desc)
		case expect == aesExpectFailure && err == nil:
			t.Errorf("%s: tampered %d-byte stream (from %d) decrypted", label, len(tampered), len(stream.wire))
		}
		if aesFuzzErrorLeaksKey(err, key) {
			t.Errorf("%s: decryption error contains key material", label)
		}
	})
}

// aesFuzzStream is an encrypted plaintext and the wire offsets that its
// authentication covers.
type aesFuzzStream struct {
	primitive *subtle.AESGCMHKDF // nil selects OpenPGP
	wire      []byte
	// authenticated holds the wire offset of each authenticated byte in stream
	// order. Whole segments of stride bytes start at first and end by end.
	authenticated      []int
	first, stride, end int
}

func newAESFuzzStream(tb testing.TB, key []byte, tink bool, chunkSel byte, plaintext []byte) *aesFuzzStream {
	tb.Helper()
	var wire bytes.Buffer
	if !tink {
		chunk := 64 << (chunkSel % 4)
		require.NoError(tb, EncryptOpenPGP(key, uint32(chunk), bytes.NewReader(plaintext), &wire))
		stream := &aesFuzzStream{wire: wire.Bytes(), first: openPGPSEIPDv2Header, stride: chunk + aesFuzzTagSize}
		// The SEIPDv2 header is checked or bound into the key and associated
		// data; only the packet's tag and length octets are framing.
		stream.authenticated, _, _ = openPGPBodyOffsets(tb, stream.wire)
		stream.end = len(stream.authenticated) - aesFuzzTagSize
		return stream
	}
	segment := 64 + 3*int(chunkSel)
	primitive, err := subtle.NewAESGCMHKDF(key, "SHA256", len(key), segment, 0)
	require.NoError(tb, err)
	require.NoError(tb, EncryptTink(primitive, bytes.NewReader(plaintext), &wire, nil))
	// The header shares the first segment, so whole segments start at the second.
	stream := &aesFuzzStream{primitive: primitive, wire: wire.Bytes(), first: segment, stride: segment, end: wire.Len()}
	stream.authenticated = make([]int, len(stream.wire))
	for i := range stream.authenticated {
		stream.authenticated[i] = i
	}
	return stream
}

func (s *aesFuzzStream) segments() int { return max(s.end-s.first, 0) / s.stride }

func (s *aesFuzzStream) segmentStart(index int) uint16 {
	return uint16(s.authenticated[s.first+index*s.stride])
}

// tamper applies one generated change and reports what decryption must do if
// the change altered the wire. Replacement may reframe the same OpenPGP body,
// and a flip in the packet's tag or length octets might, so neither must fail.
func (s *aesFuzzStream) tamper(kind byte, at uint16, extra []byte) ([]byte, int) {
	wire := bytes.Clone(s.wire)
	switch kind % aesTamperKinds {
	case aesTamperTruncate:
		return wire[:int(at)%len(wire)], aesExpectFailure
	case aesTamperAppend:
		return append(wire, extra...), aesExpectFailure
	case aesTamperFlip:
		mask := byte(1)
		if len(extra) > 0 && extra[0] != 0 {
			mask = extra[0]
		}
		offset := int(at) % len(wire)
		wire[offset] ^= mask
		if slices.Contains(s.authenticated, offset) {
			return wire, aesExpectFailure
		}
		return wire, aesExpectEither
	case aesTamperSwap:
		segments := s.segments()
		if segments < 2 {
			return wire, aesExpectFailure
		}
		i := int(at) % segments
		j := (i + 1 + int(at)/segments%(segments-1)) % segments
		for b := range s.stride {
			x, y := s.authenticated[s.first+i*s.stride+b], s.authenticated[s.first+j*s.stride+b]
			wire[x], wire[y] = wire[y], wire[x]
		}
		return wire, aesExpectFailure
	case aesTamperReplace:
		return bytes.Clone(extra), aesExpectEither
	default:
		return wire, aesExpectSuccess
	}
}

// decrypt follows aes decrypt: OpenPGP validates its header before output, and
// Tink authenticates a first read before replaying it to output.
func (s *aesFuzzStream) decrypt(key, wire []byte, output io.Writer) error {
	if s.primitive == nil {
		reader, err := PrepareOpenPGP(key, bytes.NewReader(wire))
		if err != nil {
			return err
		}
		return reader.CopyTo(output)
	}
	reader, err := s.primitive.NewDecryptingReader(bytes.NewReader(wire), nil)
	if err != nil {
		return fmt.Errorf("read Tink header: %w", err)
	}
	first := make([]byte, aesFuzzTinkFirstRead)
	n, err := reader.Read(first)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("decrypt Tink stream: %w", err)
	}
	if _, err := io.Copy(output, io.MultiReader(bytes.NewReader(first[:n]), reader)); err != nil {
		return fmt.Errorf("decrypt Tink stream: %w", err)
	}
	return nil
}

// aesFuzzOutput fails writes past the plaintext length, which no correct
// decryption reaches, so a defect cannot grow output without bound.
type aesFuzzOutput struct {
	data     []byte
	limit    int
	exceeded bool
}

func (o *aesFuzzOutput) Write(p []byte) (int, error) {
	if len(o.data)+len(p) > o.limit {
		o.exceeded = true
		return 0, errAESFuzzOutputLimit
	}
	o.data = append(o.data, p...)
	return len(p), nil
}

func aesFuzzErrorLeaksKey(err error, key []byte) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return strings.Contains(text, string(key)) || strings.Contains(strings.ToLower(text), hex.EncodeToString(key)) ||
		strings.Contains(text, base64.StdEncoding.EncodeToString(key)) || strings.Contains(text, fmt.Sprintf("%d", key))
}

// describeAESFuzzError withholds error text that contains the key.
func describeAESFuzzError(err error, key []byte) string {
	if aesFuzzErrorLeaksKey(err, key) {
		return "error text withheld: contains key material"
	}
	return fmt.Sprint(err)
}
