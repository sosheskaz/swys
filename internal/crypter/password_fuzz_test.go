package crypter

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// Preflight limits as the aes decrypt guide states them. They are restated
// rather than read from the production constants so that the oracle does not
// move with them.
const (
	guideKDFMemoryKiB = 256 << 10
	guideKDFPasses    = 10
	guideKDFLanes     = 16
	guideKDFWork      = guideKDFMemoryKiB * guideKDFPasses
	guideWrappers     = 16
)

// FuzzOpenPGPPasswordPreflight checks wrapper framing and KDF costs against an
// independent walk of the wire bytes. A message the walk can classify must be
// accepted exactly when every wrapper is within the per-wrapper limits and the
// wrappers' combined memory times passes is within the cumulative limit, and
// must otherwise fail with ErrPasswordKDFLimit. It never calls Open, so no
// fuzzed cost is ever derived.
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
	message := func(wrappers ...[]byte) []byte {
		return append(slices.Concat(wrappers...), seipd.Bytes()...)
	}
	f.Add(message(wrapper))
	f.Add(message(withCosts(wrapper, 10, 16, 18)))
	f.Add(message(withCosts(wrapper, 11, 1, 3)))
	f.Add(message(withCosts(wrapper, 1, 17, 8)))
	f.Add(message(withCosts(wrapper, 1, 1, 19)))
	f.Add(message(slices.Repeat([][]byte{withCosts(wrapper, 5, 1, 18)}, 2)...))
	f.Add(message(slices.Repeat([][]byte{withCosts(wrapper, 5, 1, 18)}, 3)...))
	f.Add(message(withCosts(wrapper, 10, 1, 18), withCosts(wrapper, 1, 1, 3)))
	f.Add(message(slices.Repeat([][]byte{wrapper}, guideWrappers+1)...))
	f.Add([]byte{0xc3, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x8f, 0x06})

	f.Fuzz(func(t *testing.T, wire []byte) {
		counted := &countingReader{reader: bytes.NewReader(wire)}
		message, err := PrepareOpenPGPPassword(counted)
		require.LessOrEqual(t, counted.read, 4096, "preflight read beyond its budget")
		wrappers, seipd := walkArgon2Wrappers(wire)
		switch expectedPreflight(wrappers, seipd) {
		case preflightAccepts:
			require.NoError(t, err)
			require.Len(t, message.wrappers, len(wrappers))
		case preflightExceedsKDFLimit:
			require.ErrorIs(t, err, ErrPasswordKDFLimit)
		case preflightRejects:
			require.Error(t, err)
		case preflightUnknown:
		}
		// These hold even where the walk cannot classify the message.
		switch {
		case err == nil:
			require.True(t, seipd, "accepted wrappers the walk cannot locate")
			require.Len(t, wrappers, len(message.wrappers))
			require.False(t, overKDFLimit(wrappers), "accepted wrappers over the KDF limits")
		case errors.Is(err, ErrPasswordKDFLimit):
			require.True(t, overKDFLimit(wrappers), "KDF limit error without an over-limit wrapper")
		}
	})
}

type preflightOutcome int

const (
	preflightUnknown preflightOutcome = iota
	preflightAccepts
	preflightExceedsKDFLimit
	preflightRejects
)

type wrapperParse int

const (
	// wrapperParses is an AES-256 SKESK v6 with valid Argon2 parameters whose IV
	// and encrypted key fit whatever the AEAD mode.
	wrapperParses wrapperParse = iota
	// wrapperFails is never a valid AES-256 SKESK v6 with Argon2.
	wrapperFails
	// wrapperUnknown has an IV and encrypted key whose split depends on the
	// AEAD mode's IV length.
	wrapperUnknown
)

// argon2Wrapper holds the Argon2 costs stored in one SKESK.
type argon2Wrapper struct {
	parse          wrapperParse
	passes         byte
	lanes          byte
	memoryExponent byte
}

// walkArgon2Wrappers locates the Argon2 costs of the SKESK packets leading
// wire using RFC 9580 framing alone. It stops at the first packet whose costs
// it cannot locate, reporting whether that packet is a SEIPD, or after one
// wrapper more than the preflight allows.
func walkArgon2Wrappers(wire []byte) ([]argon2Wrapper, bool) {
	var wrappers []argon2Wrapper
	for len(wrappers) <= guideWrappers && len(wire) > 0 {
		// Tag 18 has only a new-format header.
		if wire[0] == 0xd2 {
			return wrappers, true
		}
		body, rest, ok := skeskBody(wire)
		// RFC 9580 section 5.3: a v6 body holds version, octet count, cipher,
		// AEAD mode, S2K length, the S2K specifier, the IV, and the encrypted
		// key. An Argon2 specifier is 20 octets: mode 4, a 16-octet salt,
		// passes, lanes, and the memory exponent (section 3.7.1.4).
		if !ok || len(body) < 25 || body[4] != 20 || body[5] != 4 {
			break
		}
		costs := body[22:25]
		found := argon2Wrapper{passes: costs[0], lanes: costs[1], memoryExponent: costs[2]}
		switch tail := len(body) - 25; {
		case body[0] != 6 || body[2] != 9 || !found.rfcValid():
			found.parse = wrapperFails
		// IVs are at most 16 octets, and go-crypto rejects encrypted keys of 64
		// octets or more.
		case tail < 16 || tail > 63:
			found.parse = wrapperUnknown
		}
		wrappers = append(wrappers, found)
		wire = rest
	}
	return wrappers, false
}

// skeskBody splits a definite-length tag 3 packet from the front of wire
// (RFC 9580 section 4.2).
func skeskBody(wire []byte) ([]byte, []byte, bool) {
	var header int
	var length uint64
	switch first := wire[0]; {
	case first == 0xc3 && len(wire) >= 2 && wire[1] < 192:
		header, length = 2, uint64(wire[1])
	case first == 0xc3 && len(wire) >= 3 && wire[1] < 224:
		header, length = 3, (uint64(wire[1])-192)<<8+uint64(wire[2])+192
	case first == 0xc3 && len(wire) >= 6 && wire[1] == 255:
		header, length = 6, bigEndian(wire[2:6])
	// Legacy format with a one-, two-, or four-octet length.
	case first >= 0x8c && first <= 0x8e && len(wire) > 1<<(first&3):
		header = 1 + 1<<(first&3)
		length = bigEndian(wire[1:header])
	default:
		return nil, nil, false
	}
	rest := wire[header:]
	if length > uint64(len(rest)) {
		return nil, nil, false
	}
	return rest[:length], rest[length:], true
}

func bigEndian(octets []byte) uint64 {
	var value uint64
	for _, octet := range octets {
		value = value<<8 | uint64(octet)
	}
	return value
}

// rfcValid applies RFC 9580 section 3.7.1.4: passes and lanes are nonzero,
// and the encoded memory runs from 3+ceil(log2(lanes)) through 31.
func (w argon2Wrapper) rfcValid() bool {
	return w.passes > 0 && w.lanes > 0 && w.memoryExponent <= 31 &&
		uint64(1)<<w.memoryExponent >= 8*uint64(w.lanes)
}

func (w argon2Wrapper) withinKDFLimits() bool {
	return w.memoryExponent <= 31 && uint64(1)<<w.memoryExponent <= guideKDFMemoryKiB &&
		w.passes <= guideKDFPasses && w.lanes <= guideKDFLanes
}

// work returns memory times passes for a wrapper within the KDF limits.
func (w argon2Wrapper) work() uint64 { return uint64(w.passes) << w.memoryExponent }

// expectedPreflight re-derives the preflight outcome in its order of checks:
// wrapper count, then parsing, then each wrapper's limits, then the running
// cumulative work. A walk that ends anywhere but a SEIPD header ends at the
// end of input or at a packet the preflight cannot accept as a wrapper.
func expectedPreflight(wrappers []argon2Wrapper, seipd bool) preflightOutcome {
	var work uint64
	for i, wrapper := range wrappers {
		if i == guideWrappers {
			return preflightRejects
		}
		switch wrapper.parse {
		case wrapperFails:
			return preflightRejects
		case wrapperUnknown:
			return preflightUnknown
		case wrapperParses:
		}
		if !wrapper.withinKDFLimits() {
			return preflightExceedsKDFLimit
		}
		if work += wrapper.work(); work > guideKDFWork {
			return preflightExceedsKDFLimit
		}
	}
	if !seipd || len(wrappers) == 0 {
		return preflightRejects
	}
	return preflightAccepts
}

// overKDFLimit reports whether any located wrapper, or the running total of
// memory times passes, exceeds the guide's limits.
func overKDFLimit(wrappers []argon2Wrapper) bool {
	var work uint64
	for _, wrapper := range wrappers {
		if !wrapper.withinKDFLimits() {
			return true
		}
		if work += wrapper.work(); work > guideKDFWork {
			return true
		}
	}
	return false
}
