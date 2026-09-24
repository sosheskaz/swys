package crypter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errTestRead   = errors.New("test read failure")
	errTestWrite  = errors.New("test write failure")
	errTestSeal   = errors.New("test seal failure")
	errTestOpen   = errors.New("test open failure")
	errLateReader = errors.New("reader was called after EOF")
)

func TestAESGCMConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 64*1024*1024, maxGCMPlaintextSize)
	assert.Equal(t, 12+16, gcmWireOverhead)
}

func TestAESGCMRoundTripBoundaries(t *testing.T) {
	t.Parallel()

	for _, size := range []int{0, 1, 15, 16, 17, 65535, 65536, 65537, 2*65536 + 31} {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			t.Parallel()

			key := bytes.Repeat([]byte{byte(size + 1)}, 32)
			crypter, err := NewAESGCMCrypter(key)
			require.NoError(t, err)
			plaintext := patternedBytes(size)
			aad := []byte("exact associated data\x00")
			var ciphertext countingWriter
			require.NoError(t, crypter.Encrypt(bytes.NewReader(plaintext), &ciphertext, aad))
			require.Equal(t, 1, ciphertext.calls, "Encrypt writer calls")
			require.Len(t, ciphertext.data, size+gcmWireOverhead)

			var decrypted countingWriter
			require.NoError(t, crypter.Decrypt(bytes.NewReader(ciphertext.data), &decrypted, aad))
			require.Equal(t, 1, decrypted.calls, "Decrypt writer calls")
			if !bytes.Equal(decrypted.data, plaintext) {
				t.Fatal("round trip changed plaintext")
			}
		})
	}
}

func TestAESGCMSmallCapBoundaries(t *testing.T) {
	t.Parallel()

	const capSize = 32
	key := bytes.Repeat([]byte{0x42}, 32)
	for _, size := range []int{capSize - 1, capSize, capSize + 1} {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			t.Parallel()

			sealer := newFixedNonceCrypter(t, key, size)
			wire := encryptGCM(t, sealer, patternedBytes(size), nil)

			bounded := newFixedNonceCrypter(t, key, capSize)
			var encrypted countingWriter
			err := bounded.Encrypt(bytes.NewReader(patternedBytes(size)), &encrypted, nil)
			if size <= capSize {
				if err != nil {
					t.Fatalf("Encrypt: %v", err)
				}
				if encrypted.calls != 1 {
					t.Fatalf("Encrypt writer calls = %d, want 1", encrypted.calls)
				}
			} else {
				assertErrorIs(t, err, ErrInputTooLarge)
				assertNoWrites(t, &encrypted)
			}

			var decrypted countingWriter
			err = bounded.Decrypt(bytes.NewReader(wire), &decrypted, nil)
			if size <= capSize {
				if err != nil {
					t.Fatalf("Decrypt: %v", err)
				}
				if decrypted.calls != 1 || !bytes.Equal(decrypted.data, patternedBytes(size)) {
					t.Fatalf("Decrypt wrote %d calls and %d bytes", decrypted.calls, len(decrypted.data))
				}
			} else {
				assertErrorIs(t, err, ErrInputTooLarge)
				assertNoWrites(t, &decrypted)
			}
		})
	}
}

//nolint:paralleltest // The synthetic 64 MiB boundary case is intentionally serial to bound peak memory.
func TestAESGCMRejectsSyntheticMaximumPlusOne(t *testing.T) {
	crypter, err := NewAESGCMCrypter(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	var output countingWriter
	err = crypter.Encrypt(io.LimitReader(zeroReader{}, int64(maxGCMPlaintextSize)+1), &output, nil)
	assertErrorIs(t, err, ErrInputTooLarge)
	assertNoWrites(t, &output)
}

func TestAESGCMReaderErrorOrdering(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	crypter := newFixedNonceCrypter(t, key, 4)
	validWire := encryptGCM(t, crypter, []byte("data"), nil)
	tests := []struct {
		name    string
		steps   []readStep
		decrypt bool
	}{
		{name: "encrypt_data_and_error", steps: []readStep{{data: []byte("data"), err: errTestRead}}},
		{name: "encrypt_size_and_error", steps: []readStep{{data: []byte("large"), err: errTestRead}}},
		{name: "decrypt_malformed_and_error", decrypt: true, steps: []readStep{{data: validWire[:gcmWireOverhead-1], err: errTestRead}}},
		{name: "decrypt_size_and_error", decrypt: true, steps: []readStep{{data: append(validWire, 0), err: errTestRead}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var output countingWriter
			reader := &stepReader{steps: tt.steps}
			var err error
			if tt.decrypt {
				err = crypter.Decrypt(reader, &output, nil)
			} else {
				err = crypter.Encrypt(reader, &output, nil)
			}
			assertErrorIs(t, err, errTestRead)
			assertErrorNotIs(t, err, ErrInputTooLarge)
			assertErrorNotIs(t, err, ErrMalformedCiphertext)
			assertNoWrites(t, &output)
		})
	}
}

func TestAESGCMDoesNotReadPastMaximumPlusOne(t *testing.T) {
	t.Parallel()

	const maximum = 4
	crypter := newFixedNonceCrypter(t, make([]byte, 32), maximum)
	tests := []struct {
		run  func(io.Reader, io.Writer) error
		name string
		size int
	}{
		{
			name: "encrypt",
			size: maximum + 1,
			run: func(input io.Reader, output io.Writer) error {
				return crypter.Encrypt(input, output, nil)
			},
		},
		{
			name: "decrypt",
			size: maximum + gcmWireOverhead + 1,
			run: func(input io.Reader, output io.Writer) error {
				return crypter.Decrypt(input, output, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reader := &stepReader{steps: []readStep{{data: make([]byte, tt.size)}, {err: errLateReader}}}
			var output countingWriter
			err := tt.run(reader, &output)
			assertErrorIs(t, err, ErrInputTooLarge)
			assertErrorNotIs(t, err, errLateReader)
			assertNoWrites(t, &output)
			if reader.next != 1 {
				t.Fatalf("reader advanced to step %d, want 1", reader.next)
			}
		})
	}
}

func TestAESGCMStopsReadingAfterEOF(t *testing.T) {
	t.Parallel()

	crypter := newFixedNonceCrypter(t, make([]byte, 32), 64)
	for _, decrypt := range []bool{false, true} {
		t.Run(fmt.Sprintf("decrypt_%t", decrypt), func(t *testing.T) {
			t.Parallel()

			data := []byte("plaintext")
			if decrypt {
				data = encryptGCM(t, crypter, data, nil)
			}
			reader := &stepReader{steps: []readStep{{data: data}, {err: io.EOF}, {err: errLateReader}}}
			var output countingWriter
			var err error
			if decrypt {
				err = crypter.Decrypt(reader, &output, nil)
			} else {
				err = crypter.Encrypt(reader, &output, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			if reader.next != 2 {
				t.Fatalf("reader calls = %d, want 2", reader.next)
			}
		})
	}
}

func TestAESGCMMalformedAndAuthenticationErrors(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x11}, 32)
	crypter := newFixedNonceCrypter(t, key, 64)
	for size := range gcmWireOverhead {
		t.Run(fmt.Sprintf("malformed_%d", size), func(t *testing.T) {
			t.Parallel()

			var output countingWriter
			err := crypter.Decrypt(bytes.NewReader(make([]byte, size)), &output, nil)
			assertErrorIs(t, err, ErrMalformedCiphertext)
			assertErrorNotIs(t, err, ErrAuthenticationFailed)
			assertNoWrites(t, &output)
		})
	}
	for _, size := range []int{gcmWireOverhead, gcmWireOverhead + 1} {
		t.Run(fmt.Sprintf("authentication_%d", size), func(t *testing.T) {
			t.Parallel()

			var output countingWriter
			err := crypter.Decrypt(bytes.NewReader(make([]byte, size)), &output, nil)
			assertErrorIs(t, err, ErrAuthenticationFailed)
			assertErrorNotIs(t, err, ErrMalformedCiphertext)
			assertNoWrites(t, &output)
		})
	}
}

func TestAESGCMTamperingAndAADAreAllOrNothing(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x23}, 32)
	crypter := newFixedNonceCrypter(t, key, 256)
	plaintext := patternedBytes(33)
	aad := []byte("nonempty AAD")
	wire := encryptGCM(t, crypter, plaintext, aad)

	for byteIndex := range wire {
		for bit := range uint(8) {
			mutated := bytes.Clone(wire)
			mutated[byteIndex] ^= 1 << bit
			var output countingWriter
			err := crypter.Decrypt(bytes.NewReader(mutated), &output, aad)
			if !errors.Is(err, ErrAuthenticationFailed) {
				t.Fatalf("wire byte %d bit %d: error = %v", byteIndex, bit, err)
			}
			assertNoWrites(t, &output)
		}
	}
	for byteIndex := range aad {
		for bit := range uint(8) {
			mutated := bytes.Clone(aad)
			mutated[byteIndex] ^= 1 << bit
			var output countingWriter
			err := crypter.Decrypt(bytes.NewReader(wire), &output, mutated)
			assertErrorIs(t, err, ErrAuthenticationFailed)
			assertNoWrites(t, &output)
		}
	}
	for _, wrongAAD := range [][]byte{nil, []byte("different AAD")} {
		var output countingWriter
		err := crypter.Decrypt(bytes.NewReader(wire), &output, wrongAAD)
		assertErrorIs(t, err, ErrAuthenticationFailed)
		assertNoWrites(t, &output)
	}
}

func TestAESGCMWrongKeysFailAuthentication(t *testing.T) {
	t.Parallel()

	for _, size := range []int{16, 32} {
		t.Run(fmt.Sprintf("AES_%d", size*8), func(t *testing.T) {
			t.Parallel()

			correct := newFixedNonceCrypter(t, bytes.Repeat([]byte{1}, size), 64)
			wrong := newFixedNonceCrypter(t, bytes.Repeat([]byte{2}, size), 64)
			wire := encryptGCM(t, correct, []byte("secret"), nil)
			var output countingWriter
			err := wrong.Decrypt(bytes.NewReader(wire), &output, nil)
			assertErrorIs(t, err, ErrAuthenticationFailed)
			assertNoWrites(t, &output)
		})
	}
}

func TestAESGCMProductionAndFixedNoncePathsCrossOpen(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x7a}, 32)
	production, err := NewAESGCMCrypter(key)
	if err != nil {
		t.Fatal(err)
	}
	fixed := newFixedNonceCrypter(t, key, 128)
	plaintext := []byte("cross-open plaintext")
	aad := []byte("context")

	for _, pair := range []struct {
		sealer *AESGCMCrypter
		opener *AESGCMCrypter
		name   string
	}{
		{name: "production_to_fixed", sealer: production, opener: fixed},
		{name: "fixed_to_production", sealer: fixed, opener: production},
	} {
		t.Run(pair.name, func(t *testing.T) {
			t.Parallel()

			wire := encryptGCM(t, pair.sealer, plaintext, aad)
			var output bytes.Buffer
			if err := pair.opener.Decrypt(bytes.NewReader(wire), &output, aad); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(output.Bytes(), plaintext) {
				t.Fatal("cross-open changed plaintext")
			}
		})
	}
}

func TestAESGCMConstructorAndWireErrorsAreCausal(t *testing.T) {
	t.Parallel()

	if _, err := NewAESGCMCrypter(make([]byte, 15)); !errors.Is(err, aes.KeySizeError(15)) {
		t.Fatalf("invalid key error = %v, want errors.Is(aes.KeySizeError(15))", err)
	}
	if _, err := newAESGCMCrypter(&faultWireAEAD{overhead: gcmWireOverhead}, 0); err == nil {
		t.Fatal("zero maximum accepted")
	}
	if _, err := newAESGCMCrypter(&faultWireAEAD{overhead: gcmWireOverhead - 1}, 1); err == nil {
		t.Fatal("wrong wire overhead accepted")
	}

	sealCrypter, err := newAESGCMCrypter(&faultWireAEAD{overhead: gcmWireOverhead, sealErr: errTestSeal}, 64)
	if err != nil {
		t.Fatal(err)
	}
	var output countingWriter
	err = sealCrypter.Encrypt(bytes.NewReader([]byte("data")), &output, nil)
	assertErrorIs(t, err, errTestSeal)
	assertNoWrites(t, &output)

	openCrypter, err := newAESGCMCrypter(&faultWireAEAD{overhead: gcmWireOverhead, openErr: errTestOpen}, 64)
	if err != nil {
		t.Fatal(err)
	}
	err = openCrypter.Decrypt(bytes.NewReader(make([]byte, gcmWireOverhead)), &output, nil)
	assertErrorIs(t, err, errTestOpen)
	assertErrorIs(t, err, ErrAuthenticationFailed)
	assertNoWrites(t, &output)
}

func TestNewAESGCMCrypterRejectsNilAEAD(t *testing.T) {
	t.Parallel()

	crypter, err := newAESGCMCrypter(nil, 1)
	if err == nil {
		t.Fatalf("newAESGCMCrypter(nil, 1) = %#v, nil; want error", crypter)
	}
}

func TestNewAESGCMCrypterRejectsOverflowingMaximum(t *testing.T) {
	t.Parallel()

	wire := &faultWireAEAD{overhead: gcmWireOverhead}
	for _, maximum := range []int{
		math.MaxInt,
		math.MaxInt - gcmWireOverhead + 1,
	} {
		t.Run(fmt.Sprintf("maximum_%d", maximum), func(t *testing.T) {
			t.Parallel()

			crypter, err := newAESGCMCrypter(wire, maximum)
			if err == nil {
				t.Fatalf("newAESGCMCrypter maximum %d = %#v, nil; want error", maximum, crypter)
			}
		})
	}
}

func TestAESGCMNonceSourceErrorsAreCausal(t *testing.T) {
	t.Parallel()

	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	wire := &fixedNonceWireAEAD{aead: aead, nonceSource: &stepReader{steps: []readStep{{data: make([]byte, 6), err: errTestRead}}}}
	crypter, err := newAESGCMCrypter(wire, 64)
	if err != nil {
		t.Fatal(err)
	}
	var output countingWriter
	err = crypter.Encrypt(bytes.NewReader([]byte("data")), &output, nil)
	assertErrorIs(t, err, errTestRead)
	assertNoWrites(t, &output)
}

func TestAESGCMForwardsExactAADBytes(t *testing.T) {
	t.Parallel()

	underlying := newFixedNonceWireAEAD(t, make([]byte, 32), zeroReader{})
	recording := &recordingWireAEAD{gcmWireAEAD: underlying}
	crypter, err := newAESGCMCrypter(recording, 64)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte{0x00, 0xff, 0x61, 0x00, 0x62}
	wire := encryptGCM(t, crypter, []byte("data"), aad)
	if !bytes.Equal(recording.sealAAD, aad) {
		t.Fatalf("Seal AAD = %x, want %x", recording.sealAAD, aad)
	}
	var output bytes.Buffer
	if err := crypter.Decrypt(bytes.NewReader(wire), &output, aad); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recording.openAAD, aad) {
		t.Fatalf("Open AAD = %x, want %x", recording.openAAD, aad)
	}
}

func TestAESGCMWriterErrorsUseOneCall(t *testing.T) {
	t.Parallel()

	crypter := newFixedNonceCrypter(t, make([]byte, 32), 64)
	wire := encryptGCM(t, crypter, []byte("data"), nil)
	for _, tt := range []struct {
		wantErr error
		writer  *countingWriter
		name    string
	}{
		{name: "encrypt_failure", writer: &countingWriter{err: errTestWrite}, wantErr: errTestWrite},
		{name: "encrypt_short", writer: &countingWriter{short: true}, wantErr: io.ErrShortWrite},
		{name: "decrypt_failure", writer: &countingWriter{err: errTestWrite}, wantErr: errTestWrite},
		{name: "decrypt_short", writer: &countingWriter{short: true}, wantErr: io.ErrShortWrite},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var err error
			if strings.HasPrefix(tt.name, "decrypt") {
				err = crypter.Decrypt(bytes.NewReader(wire), tt.writer, nil)
			} else {
				err = crypter.Encrypt(bytes.NewReader([]byte("data")), tt.writer, nil)
			}
			assertErrorIs(t, err, tt.wantErr)
			if tt.writer.calls != 1 {
				t.Fatalf("writer calls = %d, want 1", tt.writer.calls)
			}
		})
	}
}

type fixedNonceWireAEAD struct {
	aead        cipher.AEAD
	nonceSource io.Reader
}

func (a *fixedNonceWireAEAD) Overhead() int { return a.aead.NonceSize() + a.aead.Overhead() }

func (a *fixedNonceWireAEAD) Seal(dst, plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, a.aead.NonceSize())
	if _, err := io.ReadFull(a.nonceSource, nonce); err != nil {
		return nil, fmt.Errorf("read fixed nonce: %w", err)
	}
	dst = append(dst, nonce...)
	return a.aead.Seal(dst, nonce, plaintext, aad), nil
}

func (a *fixedNonceWireAEAD) Open(dst, ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < a.Overhead() {
		return nil, ErrMalformedCiphertext
	}
	nonceSize := a.aead.NonceSize()
	opened, err := a.aead.Open(dst, ciphertext[:nonceSize], ciphertext[nonceSize:], aad)
	if err != nil {
		return nil, fmt.Errorf("open fixed-nonce ciphertext: %w", err)
	}
	return opened, nil
}

type faultWireAEAD struct {
	sealErr  error
	openErr  error
	overhead int
}

func (a *faultWireAEAD) Overhead() int                       { return a.overhead }
func (a *faultWireAEAD) Seal(_, _, _ []byte) ([]byte, error) { return nil, a.sealErr }
func (a *faultWireAEAD) Open(_, _, _ []byte) ([]byte, error) { return nil, a.openErr }

type recordingWireAEAD struct {
	gcmWireAEAD
	sealAAD []byte
	openAAD []byte
}

func (a *recordingWireAEAD) Seal(dst, plaintext, aad []byte) ([]byte, error) {
	a.sealAAD = bytes.Clone(aad)
	return a.gcmWireAEAD.Seal(dst, plaintext, aad)
}

func (a *recordingWireAEAD) Open(dst, ciphertext, aad []byte) ([]byte, error) {
	a.openAAD = bytes.Clone(aad)
	return a.gcmWireAEAD.Open(dst, ciphertext, aad)
}

type countingWriter struct {
	err   error
	data  []byte
	calls int
	short bool
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.err != nil {
		return 0, w.err
	}
	if w.short && len(p) > 0 {
		w.data = append(w.data, p[:len(p)-1]...)
		return len(p) - 1, nil
	}
	w.data = append(w.data, p...)
	return len(p), nil
}

type readStep struct {
	err  error
	data []byte
}

type stepReader struct {
	steps []readStep
	next  int
}

func (r *stepReader) Read(p []byte) (int, error) {
	if r.next >= len(r.steps) {
		return 0, io.EOF
	}
	step := &r.steps[r.next]
	n := copy(p, step.data)
	step.data = step.data[n:]
	if len(step.data) == 0 {
		r.next++
		return n, step.err
	}
	return n, nil
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func newFixedNonceCrypter(t *testing.T, key []byte, maximum int) *AESGCMCrypter {
	t.Helper()
	wire := newFixedNonceWireAEAD(t, key, zeroReader{})
	crypter, err := newAESGCMCrypter(wire, maximum)
	if err != nil {
		t.Fatal(err)
	}
	return crypter
}

func newFixedNonceWireAEAD(t *testing.T, key []byte, nonceSource io.Reader) *fixedNonceWireAEAD {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return &fixedNonceWireAEAD{aead: aead, nonceSource: nonceSource}
}

func encryptGCM(t *testing.T, crypter *AESGCMCrypter, plaintext, aad []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	if err := crypter.Encrypt(bytes.NewReader(plaintext), &output, aad); err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(output.Bytes())
}

func patternedBytes(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*31 + 7)
	}
	return data
}

func assertNoWrites(t *testing.T, writer *countingWriter) {
	t.Helper()
	if writer.calls != 0 || len(writer.data) != 0 {
		t.Fatalf("writer received %d calls and %d bytes, want none", writer.calls, len(writer.data))
	}
}

func assertErrorIs(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want errors.Is(_, %v)", err, target)
	}
}

func assertErrorNotIs(t *testing.T, err, target error) {
	t.Helper()
	if errors.Is(err, target) {
		t.Fatalf("error = %v, unexpectedly errors.Is(_, %v)", err, target)
	}
}
