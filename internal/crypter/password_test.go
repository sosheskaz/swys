package crypter

import (
	"bytes"
	"io"
	"slices"
	"testing"
	"testing/iotest"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
	pgp "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/stretchr/testify/require"
)

var (
	testPassword     = []byte("synthetic password")
	cheapArgon2      = Argon2Parameters{MemoryKiB: 8, Passes: 1, Parallelism: 1}
	testSessionKey   = bytes.Repeat([]byte{0x5a}, 32)
	cheapWrapperS2K  = &s2k.Config{S2KMode: s2k.Argon2S2K, Argon2Config: &s2k.Argon2Config{NumberOfPasses: 1, DegreeOfParallelism: 1, Memory: 8}}
	testPlaintextPGP = []byte("password plaintext\x00\xff")
)

// testWrapper serializes a cheap SKESK for testSessionKey; costs may be patched
// afterwards because preflight tests never derive.
func testWrapper(t *testing.T, password []byte, config *packet.Config) []byte {
	t.Helper()
	if config == nil {
		config = &packet.Config{DefaultCipher: packet.CipherAES256, S2KConfig: cheapWrapperS2K}
	}
	var wrapper bytes.Buffer
	require.NoError(t, packet.SerializeSymmetricKeyEncryptedAEADReuseKey(&wrapper, testSessionKey, password, true, config))
	return wrapper.Bytes()
}

func withCosts(wrapper []byte, passes, lanes, memoryExponent byte) []byte {
	changed := bytes.Clone(wrapper)
	changed[24], changed[25], changed[26] = passes, lanes, memoryExponent
	return changed
}

func testSEIPD(t *testing.T) []byte {
	t.Helper()
	var seipd bytes.Buffer
	require.NoError(t, EncryptOpenPGP(testSessionKey, 64, bytes.NewReader(testPlaintextPGP), &seipd))
	return seipd.Bytes()
}

func TestArgon2ParametersRejectRoundingAndLimits(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		want   error
		name   string
		params Argon2Parameters
	}{
		{name: "default", params: DefaultArgon2Parameters()},
		{name: "exact limits", params: Argon2Parameters{MemoryKiB: 256 << 10, Passes: 10, Parallelism: 16}},
		{name: "smallest", params: Argon2Parameters{MemoryKiB: 8, Passes: 1, Parallelism: 1}},
		{name: "memory over", params: Argon2Parameters{MemoryKiB: 512 << 10, Passes: 1, Parallelism: 1}, want: ErrPasswordKDFLimit},
		{name: "passes over", params: Argon2Parameters{MemoryKiB: 8, Passes: 11, Parallelism: 1}, want: ErrPasswordKDFLimit},
		{name: "lanes over", params: Argon2Parameters{MemoryKiB: 256, Passes: 1, Parallelism: 17}, want: ErrPasswordKDFLimit},
		{name: "not power of two", params: Argon2Parameters{MemoryKiB: 96, Passes: 1, Parallelism: 1}, want: ErrInvalidArgon2Parameters},
		{name: "below lane floor", params: Argon2Parameters{MemoryKiB: 16, Passes: 1, Parallelism: 4}, want: ErrInvalidArgon2Parameters},
		{name: "zero passes", params: Argon2Parameters{MemoryKiB: 8, Parallelism: 1}, want: ErrInvalidArgon2Parameters},
		{name: "zero lanes", params: Argon2Parameters{MemoryKiB: 8, Passes: 1}, want: ErrInvalidArgon2Parameters},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := test.params.Validate()
			if test.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, test.want)
		})
	}
}

func TestPasswordWrapperStoresExactCosts(t *testing.T) {
	t.Parallel()
	prepared, err := PreparePasswordOpenPGP(testPassword, Argon2Parameters{MemoryKiB: 64, Passes: 2, Parallelism: 2})
	require.NoError(t, err)
	body, err := packetBody(prepared.wrapper)
	require.NoError(t, err)
	require.Equal(t, byte(6), body[0])
	require.Equal(t, byte(packet.CipherAES256), body[2])
	require.Equal(t, []byte{2, 2, 6}, body[22:25], "passes, lanes, log2(64 KiB)")
}

func TestPasswordPreflightAcceptsExactLimitsWithoutDerivation(t *testing.T) {
	t.Parallel()
	wrapper := testWrapper(t, testPassword, nil)
	seipd := testSEIPD(t)
	five := append([]byte{0xc3, 0xff, 0, 0, 0, wrapper[1]}, wrapper[2:]...)
	legacy := append([]byte{0x8c, wrapper[1]}, wrapper[2:]...)
	for _, test := range []struct {
		want     error
		name     string
		wrappers [][]byte
	}{
		{name: "per-wrapper limits", wrappers: [][]byte{withCosts(wrapper, 10, 16, 18)}},
		{name: "cumulative limit", wrappers: [][]byte{withCosts(wrapper, 5, 1, 18), withCosts(wrapper, 5, 1, 18)}},
		{name: "wrapper count", wrappers: slices.Repeat([][]byte{wrapper}, 16)},
		{name: "length encodings", wrappers: [][]byte{five, legacy}},
		{name: "cumulative over", wrappers: [][]byte{withCosts(wrapper, 10, 1, 18), withCosts(wrapper, 1, 1, 3)}, want: ErrPasswordKDFLimit},
		{name: "memory over", wrappers: [][]byte{withCosts(wrapper, 1, 1, 19)}, want: ErrPasswordKDFLimit},
		{name: "SKESK v4", wrappers: [][]byte{testWrapperV4(t)}, want: errPasswordWrapper},
		{name: "iterated S2K", wrappers: [][]byte{testWrapper(t, testPassword, &packet.Config{DefaultCipher: packet.CipherAES256})}, want: errPasswordWrapper},
		{name: "AES-128 KEK", want: errPasswordWrapper, wrappers: [][]byte{
			testWrapper(t, testPassword, &packet.Config{DefaultCipher: packet.CipherAES128, S2KConfig: cheapWrapperS2K}),
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			wire := append(slices.Concat(test.wrappers...), seipd...)
			message, err := PrepareOpenPGPPassword(bytes.NewReader(wire))
			if test.want != nil {
				require.ErrorIs(t, err, test.want)
				return
			}
			require.NoError(t, err)
			require.Len(t, message.wrappers, len(test.wrappers))
		})
	}
}

func testWrapperV4(t *testing.T) []byte {
	t.Helper()
	var wrapper bytes.Buffer
	config := &packet.Config{DefaultCipher: packet.CipherAES256, S2KConfig: cheapWrapperS2K}
	require.NoError(t, packet.SerializeSymmetricKeyEncryptedAEADReuseKey(&wrapper, testSessionKey, testPassword, false, config))
	return wrapper.Bytes()
}

func TestPasswordOpenTriesEachWrapper(t *testing.T) {
	t.Parallel()
	wire := slices.Concat(testWrapper(t, []byte("synthetic first"), nil), testWrapper(t, testPassword, nil), testSEIPD(t))
	message, err := PrepareOpenPGPPassword(bytes.NewReader(wire))
	require.NoError(t, err)
	reader, err := message.Open(testPassword)
	require.NoError(t, err)
	var opened bytes.Buffer
	require.NoError(t, reader.CopyTo(&opened))
	require.Equal(t, testPlaintextPGP, opened.Bytes())

	message, err = PrepareOpenPGPPassword(bytes.NewReader(wire))
	require.NoError(t, err)
	_, err = message.Open([]byte("synthetic wrong"))
	require.ErrorIs(t, err, ErrOpenPGPPassword)
}

func TestPasswordInteroperatesWithGopenPGP(t *testing.T) {
	t.Parallel()
	prepared, err := PreparePasswordOpenPGP(testPassword, cheapArgon2)
	require.NoError(t, err)
	var wire bytes.Buffer
	require.NoError(t, prepared.Encrypt(64, bytes.NewReader(testPlaintextPGP), &wire))
	decryption, err := pgp.PGPWithProfile(profile.RFC9580()).Decryption().Password(testPassword).New()
	require.NoError(t, err)
	result, err := decryption.Decrypt(wire.Bytes(), pgp.Bytes)
	require.NoError(t, err)
	require.Equal(t, testPlaintextPGP, result.Bytes())

	native := profile.RFC9580()
	native.S2kEncryption = cheapWrapperS2K
	encryption, err := pgp.PGPWithProfile(native).Encryption().Password(testPassword).New()
	require.NoError(t, err)
	message, err := encryption.Encrypt(testPlaintextPGP)
	require.NoError(t, err)
	prepared2, err := PrepareOpenPGPPassword(bytes.NewReader(message.Bytes()))
	require.NoError(t, err)
	reader, err := prepared2.Open(testPassword)
	require.NoError(t, err)
	var opened bytes.Buffer
	require.NoError(t, reader.CopyTo(&opened))
	require.Equal(t, testPlaintextPGP, opened.Bytes())
}

func TestPasswordStreamRejectsDamageAndPreservesIOErrors(t *testing.T) {
	t.Parallel()
	prepared, err := PreparePasswordOpenPGP(testPassword, cheapArgon2)
	require.NoError(t, err)
	plaintext := bytes.Repeat([]byte("segment\x00"), 32)
	var wire bytes.Buffer
	require.NoError(t, prepared.Encrypt(64, bytes.NewReader(plaintext), &wire))

	require.ErrorIs(t, prepared.Encrypt(64, bytes.NewReader(plaintext), aesShortWriter{}), io.ErrShortWrite)
	require.ErrorIs(t, prepared.Encrypt(64, bytes.NewReader(plaintext), &aesFirstShortWriter{}), io.ErrShortWrite)
	require.ErrorIs(t, prepared.Encrypt(64, bytes.NewReader(plaintext), aesErrorWriter{errAESInput}), errAESInput)

	var interrupted bytes.Buffer
	err = prepared.Encrypt(64, io.MultiReader(bytes.NewReader(plaintext), iotest.ErrReader(errAESInput)), &interrupted)
	require.ErrorIs(t, err, errAESInput)
	partial, err := PrepareOpenPGPPassword(bytes.NewReader(interrupted.Bytes()))
	if err == nil {
		reader, openErr := partial.Open(testPassword)
		if err = openErr; err == nil {
			err = reader.CopyTo(io.Discard)
		}
	}
	require.Error(t, err, "interrupted encryption produced a valid shortened message")

	finalTag := bytes.Clone(wire.Bytes())
	finalTag[len(finalTag)-1] ^= 1
	middle := bytes.Clone(wire.Bytes())
	middle[len(middle)/2] ^= 1
	for name, damaged := range map[string][]byte{
		"tampered final tag":    finalTag,
		"tampered middle chunk": middle,
		"truncated":             wire.Bytes()[:wire.Len()-1],
		"trailing data":         append(bytes.Clone(wire.Bytes()), 0xc3),
	} {
		message, err := PrepareOpenPGPPassword(bytes.NewReader(damaged))
		require.NoError(t, err, name)
		reader, err := message.Open(testPassword)
		require.NoError(t, err, name)
		var opened bytes.Buffer
		require.Error(t, reader.CopyTo(&opened), name)
		require.True(t, bytes.HasPrefix(plaintext, opened.Bytes()), "%s released unauthenticated bytes", name)
		if name == "tampered middle chunk" {
			require.Less(t, opened.Len(), len(plaintext)/2+64, "bytes from the failed chunk were released")
		}
	}
}

func TestPasswordPreflightReadsBoundedInput(t *testing.T) {
	t.Parallel()
	wrapper := testWrapper(t, testPassword, nil)
	counted := &countingReader{reader: io.MultiReader(bytes.NewReader(bytes.Repeat(wrapper, 64)), bytes.NewReader(testSEIPD(t)))}
	_, err := PrepareOpenPGPPassword(counted)
	require.Error(t, err)
	require.LessOrEqual(t, counted.read, 4096)
}

type countingReader struct {
	reader io.Reader
	read   int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.read += n
	return n, err //nolint:wrapcheck // io.Reader must preserve io.EOF identity.
}
