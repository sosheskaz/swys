package encoding

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errTestSourceReadFailed = errors.New("test source read failure")
	errTestWriteFailed      = errors.New("write failed")
)

func TestInputDecoders(t *testing.T) {
	t.Parallel()
	for _, name := range Names() {
		t.Run(name+"/empty", func(t *testing.T) {
			t.Parallel()
			decoder, err := GetInputDecoder(name)
			require.NoError(t, err)
			decoded, err := io.ReadAll(decoder(bytes.NewReader(nil)))
			require.NoError(t, err)
			assert.Empty(t, decoded)
		})
	}

	tests := []struct {
		wantErrIs error
		name      string
		encoding  string
		input     string
		want      string
		wantErr   bool
	}{
		{name: "base64 padded", encoding: "base64", input: "aGVsbG8=", want: "hello"},
		{name: "base64 truncated padding", encoding: "base64", input: "YQ=", wantErr: true},
		{name: "base64 embedded newline", encoding: "base64", input: "aGVs\nbG8=", want: "hello"},
		{name: "base64 embedded space", encoding: "base64", input: "aGVs bG8=", wantErr: true},
		{name: "base64 wrong alphabet", encoding: "base64", input: "aGVsbG8_", wantErr: true},
		{name: "base64 garbage", encoding: "base64", input: "*", wantErr: true},
		{name: "base64url raw", encoding: "base64url", input: "aGVsbG8", want: "hello"},
		{name: "base64url padded", encoding: "base64url", input: "aGVsbG8=", want: "hello"},
		{name: "base64url invalid padding", encoding: "base64url", input: "aGVsbG8==", wantErr: true, wantErrIs: errInvalidBase64URLPadding},
		{name: "base64url embedded newline", encoding: "base64url", input: "aGVs\nbG8=", want: "hello"},
		{name: "base64url embedded space", encoding: "base64url", input: "aGVs bG8=", wantErr: true},
		{name: "base64url wrong alphabet", encoding: "base64url", input: "aGVsbG8+", wantErr: true},
		{name: "base64url garbage", encoding: "base64url", input: "*", wantErr: true},
		{name: "base32 valid", encoding: "base32", input: "NBSWY3DP", want: "hello"},
		{name: "base32 truncated padding", encoding: "base32", input: "ME=====", wantErr: true},
		{name: "base32 wrong alphabet", encoding: "base32", input: "00", wantErr: true},
		{name: "base32 embedded space", encoding: "base32", input: "NBSW Y3DP", wantErr: true},
		{name: "base32 garbage", encoding: "base32", input: "*", wantErr: true},
		{name: "hex valid", encoding: "hex", input: "68656c6c6f", want: "hello"},
		{name: "hex trailing newline", encoding: "hex", input: "68656c6c6f\n", want: "hello"},
		{name: "hex embedded newline", encoding: "hex", input: "6865\n6c6c6f", want: "hello"},
		{name: "hex truncated byte", encoding: "hex", input: "6", wantErr: true},
		{name: "hex wrong alphabet", encoding: "hex", input: "gg", wantErr: true},
		{name: "hex embedded space", encoding: "hex", input: "68 65", wantErr: true},
		{name: "hex garbage", encoding: "hex", input: "*", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			decoder, err := GetInputDecoder(test.encoding)
			require.NoError(t, err)
			decoded, err := io.ReadAll(decoder(bytes.NewBufferString(test.input)))
			if test.wantErr {
				require.Error(t, err, "decode %q = %q", test.input, decoded)
				if test.wantErrIs != nil {
					require.ErrorIs(t, err, test.wantErrIs, "decode %q", test.input)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, string(decoded), "decode %q", test.input)
		})
	}
}

func TestOutputEncodersPropagateWriterFailures(t *testing.T) {
	t.Parallel()
	writeErr := errTestWriteFailed
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			encoder, err := GetOutputEncoder(name)
			require.NoError(t, err)
			output, closer := encoder(failingWriter{err: writeErr})
			_, err = output.Write(make([]byte, 64))
			if closer != nil {
				err = errors.Join(err, closer.Close())
			}
			assert.ErrorIs(t, err, writeErr)
		})
	}
}

func TestBase64URLValidationErrorOmitsEOF(t *testing.T) {
	t.Parallel()
	decoder, err := GetInputDecoder("base64url")
	require.NoError(t, err)
	_, err = io.ReadAll(decoder(strings.NewReader("YWJ=Z")))
	require.ErrorIs(t, err, errInvalidBase64URLPadding)
	assert.NotContains(t, err.Error(), "EOF")
}

func TestBase64DecodersRejectDataAfterTerminalPadding(t *testing.T) {
	t.Parallel()
	const validationBufferSize = 32 << 10
	readBufferSizes := []int{1, 4, validationBufferSize - 1, validationBufferSize, validationBufferSize + 1}
	inputs := map[string]string{
		"single padding":         "000=0000",
		"double padding":         "YQ==Yg==",
		"buffer boundary":        strings.Repeat("AAAA", validationBufferSize/4-1) + "YQ==Yg==",
		"split padding and CRLF": "YQ=\r\n=Yg==",
	}

	for _, name := range []string{"base64", "b64"} {
		for inputName, input := range inputs {
			for _, readBufferSize := range readBufferSizes {
				t.Run(fmt.Sprintf("%s/%s/read-%d", name, inputName, readBufferSize), func(t *testing.T) {
					t.Parallel()
					decoder, err := GetInputDecoder(name)
					require.NoError(t, err)
					reader := decoder(&maxChunkReader{
						source: strings.NewReader(input),
						max:    readBufferSize,
					})
					_, err = readAllWithBuffer(reader, readBufferSize)
					require.Error(t, err, "decode accepted data after terminal padding with read buffer %d", readBufferSize)
					n, stickyErr := reader.Read(make([]byte, 1))
					assert.Zero(t, n, "read after validation error")
					assert.EqualError(t, stickyErr, err.Error(), "sticky validation error")
				})
			}
		}
	}
}

func TestBase64DecodersPreserveValidPaddingPolicyAcrossBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "padded", input: "YQ==", want: "a"},
		{name: "CRLF within padding", input: "YQ=\r\n=", want: "a"},
		{name: "non-zero pad bits remain accepted", input: "Zh==", want: "f"},
	}
	for _, encodingName := range []string{"base64", "b64"} {
		for _, test := range tests {
			for _, sourceChunkSize := range []int{1, 4} {
				t.Run(fmt.Sprintf("%s/%s/source-%d", encodingName, test.name, sourceChunkSize), func(t *testing.T) {
					t.Parallel()
					decoder, err := GetInputDecoder(encodingName)
					require.NoError(t, err)
					got, err := io.ReadAll(decoder(&maxChunkReader{
						source: strings.NewReader(test.input),
						max:    sourceChunkSize,
					}))
					require.NoError(t, err)
					assert.Equal(t, test.want, string(got))
				})
			}
		}
	}
}

func TestBase64DecoderPreservesSourceErrorWithData(t *testing.T) {
	t.Parallel()
	readErr := errTestSourceReadFailed
	source := &dataAndErrorReader{data: []byte("YQ=="), err: readErr}
	decoder, err := GetInputDecoder("base64")
	require.NoError(t, err)
	reader := decoder(source)
	got, err := readAllWithBuffer(reader, 1)
	assert.Equal(t, "a", string(got), "decoded bytes")
	require.ErrorIs(t, err, readErr, "decode error")

	n, stickyErr := reader.Read(make([]byte, 1))
	assert.Zero(t, n, "read after source error")
	require.ErrorIs(t, stickyErr, readErr, "sticky source error")
	assert.Equal(t, 1, source.reads, "source reads")
}

func TestBase64ValidationErrorOmitsEOF(t *testing.T) {
	t.Parallel()
	source := &dataAndErrorReader{data: []byte("YQ==Yg=="), err: io.EOF}
	decoder, err := GetInputDecoder("base64")
	require.NoError(t, err)
	got, err := io.ReadAll(decoder(source))
	assert.Equal(t, "a", string(got), "decoded prefix")
	require.ErrorIs(t, err, errInvalidBase64Padding, "decode error")
	assert.NotErrorIs(t, err, io.EOF, "decode error must not expose EOF")
}

func TestNewlineStrippingReaderDoesNotReturnZeroWithoutError(t *testing.T) {
	t.Parallel()
	source := &sequenceReader{chunks: [][]byte{[]byte("\r\n\r\n"), []byte("ab")}}
	reader := stripNewlines(source)
	buffer := make([]byte, 8)
	n, err := reader.Read(buffer)
	require.NoError(t, err)
	require.NotZero(t, n, "read returned 0 bytes with nil error for a non-empty buffer, want the newline-only chunk skipped internally")
	assert.Equal(t, "ab", string(buffer[:n]))
}

type sequenceReader struct {
	err    error
	chunks [][]byte
}

type maxChunkReader struct {
	source io.Reader
	max    int
}

func (reader *maxChunkReader) Read(buffer []byte) (int, error) {
	if len(buffer) > reader.max {
		buffer = buffer[:reader.max]
	}
	return reader.source.Read(buffer) //nolint:wrapcheck // preserve error identity for decoder propagation tests
}

type dataAndErrorReader struct {
	err   error
	data  []byte
	reads int
}

func (reader *dataAndErrorReader) Read(buffer []byte) (int, error) {
	reader.reads++
	if reader.reads > 1 {
		return 0, io.EOF
	}
	return copy(buffer, reader.data), reader.err
}

func readAllWithBuffer(reader io.Reader, bufferSize int) ([]byte, error) {
	var output bytes.Buffer
	buffer := make([]byte, bufferSize)
	for {
		read, err := reader.Read(buffer)
		if read > 0 {
			_, _ = output.Write(buffer[:read])
		}
		if err != nil {
			if err == io.EOF {
				return output.Bytes(), nil
			}
			return output.Bytes(), err
		}
		if read == 0 {
			return output.Bytes(), io.ErrNoProgress
		}
	}
}

func (r *sequenceReader) Read(buffer []byte) (int, error) {
	if len(r.chunks) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		return 0, io.EOF
	}
	n := copy(buffer, r.chunks[0])
	r.chunks[0] = r.chunks[0][n:]
	if len(r.chunks[0]) == 0 {
		r.chunks = r.chunks[1:]
	}
	return n, nil
}

func TestOptionalPaddingReaderErrorIsSticky(t *testing.T) {
	t.Parallel()
	reader := &optionalPaddingReader{source: strings.NewReader("YWJ=Z")}
	buffer := make([]byte, 8)

	var firstErr error
	for range 8 {
		_, firstErr = reader.Read(buffer)
		if firstErr != nil {
			break
		}
	}
	require.Error(t, firstErr, "no error surfaced within 8 reads, want invalid padding")
	require.ErrorIs(t, firstErr, errInvalidBase64URLPadding)

	n, secondErr := reader.Read(buffer)
	assert.Zero(t, n, "read after error")
	assert.ErrorIs(t, secondErr, errInvalidBase64URLPadding, "sticky invalid padding error")
}

type failingWriter struct {
	err error
}

func (writer failingWriter) Write([]byte) (int, error) {
	return 0, writer.err
}

func BenchmarkOutputEncodings(b *testing.B) {
	for _, name := range Names() {
		for _, size := range benchmarkEncodingSizes {
			b.Run(fmt.Sprintf("%s/%s", name, size.name), func(b *testing.B) {
				data := make([]byte, size.bytes)
				encoder, err := GetOutputEncoder(name)
				if err != nil {
					b.Fatal(err)
				}

				b.SetBytes(int64(len(data)))
				b.ReportAllocs()
				for b.Loop() {
					output, closer := encoder(io.Discard)
					if _, err := io.Copy(output, bytes.NewReader(data)); err != nil {
						b.Fatal(err)
					}
					if closer != nil {
						if err := closer.Close(); err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	}
}

func BenchmarkInputDecodings(b *testing.B) {
	for _, name := range Names() {
		for _, size := range benchmarkEncodingSizes {
			b.Run(fmt.Sprintf("%s/%s", name, size.name), func(b *testing.B) {
				encoded := encodeBenchmarkInput(b, name, make([]byte, size.bytes))
				decoder, err := GetInputDecoder(name)
				if err != nil {
					b.Fatal(err)
				}

				b.SetBytes(int64(size.bytes))
				b.ReportAllocs()
				for b.Loop() {
					if _, err := io.Copy(io.Discard, decoder(bytes.NewReader(encoded))); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

var benchmarkEncodingSizes = []struct {
	name  string
	bytes int
}{
	{name: "4KB", bytes: 4 << 10},
	{name: "64KB", bytes: 64 << 10},
	{name: "1MB", bytes: 1 << 20},
}

func encodeBenchmarkInput(b *testing.B, name string, input []byte) []byte {
	b.Helper()
	encoder, err := GetOutputEncoder(name)
	if err != nil {
		b.Fatal(err)
	}
	var output bytes.Buffer
	writer, closer := encoder(&output)
	if _, err := writer.Write(input); err != nil {
		b.Fatal(err)
	}
	if closer != nil {
		if err := closer.Close(); err != nil {
			b.Fatal(err)
		}
	}
	return output.Bytes()
}
