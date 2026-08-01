package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

var errTestWriteFailed = errors.New("write failed")

func TestInputDecoders(t *testing.T) {
	for _, name := range byteEncodingNames() {
		t.Run(name+"/empty", func(t *testing.T) {
			decoder, err := getInputDecoder(name)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := io.ReadAll(decoder(bytes.NewReader(nil)))
			if err != nil || len(decoded) != 0 {
				t.Fatalf("empty decode = %x, %v; want empty success", decoded, err)
			}
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
			decoder, err := getInputDecoder(test.encoding)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := io.ReadAll(decoder(bytes.NewBufferString(test.input)))
			if test.wantErr {
				if err == nil {
					t.Fatalf("decode %q = %q, want error", test.input, decoded)
				}
				if test.wantErrIs != nil && !errors.Is(err, test.wantErrIs) {
					t.Fatalf("decode %q error = %v, want %v", test.input, err, test.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(decoded) != test.want {
				t.Fatalf("decode %q = %q, want %q", test.input, decoded, test.want)
			}
		})
	}
}

func TestOutputEncodersPropagateWriterFailures(t *testing.T) {
	writeErr := errTestWriteFailed
	for _, name := range byteEncodingNames() {
		t.Run(name, func(t *testing.T) {
			encoder, err := getOutputEncoder(name)
			if err != nil {
				t.Fatal(err)
			}
			output, closer := encoder(failingWriter{err: writeErr})
			_, err = output.Write(make([]byte, 64))
			if closer != nil {
				err = errors.Join(err, closer.Close())
			}
			if !errors.Is(err, writeErr) {
				t.Fatalf("error = %v, want writer failure", err)
			}
		})
	}
}

func TestBase64URLValidationErrorOmitsEOF(t *testing.T) {
	decoder, err := getInputDecoder("base64url")
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(decoder(strings.NewReader("YWJ=Z")))
	if err == nil || !errors.Is(err, errInvalidBase64URLPadding) {
		t.Fatalf("error = %v, want invalid padding", err)
	}
	if strings.Contains(err.Error(), "EOF") {
		t.Fatalf("error = %q, want no EOF suffix", err)
	}
}

func TestNewlineStrippingReaderDoesNotReturnZeroWithoutError(t *testing.T) {
	source := &sequenceReader{chunks: [][]byte{[]byte("\r\n\r\n"), []byte("ab")}}
	reader := stripNewlines(source)
	buffer := make([]byte, 8)
	n, err := reader.Read(buffer)
	if err != nil {
		t.Fatalf("read error = %v, want nil", err)
	}
	if n == 0 {
		t.Fatal("read returned 0 bytes with nil error for a non-empty buffer, want the newline-only chunk skipped internally")
	}
	if string(buffer[:n]) != "ab" {
		t.Fatalf("read = %q, want %q", buffer[:n], "ab")
	}
}

type sequenceReader struct {
	err    error
	chunks [][]byte
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
	reader := &optionalPaddingReader{source: strings.NewReader("YWJ=Z")}
	buffer := make([]byte, 8)

	var firstErr error
	for range 8 {
		_, firstErr = reader.Read(buffer)
		if firstErr != nil {
			break
		}
	}
	if firstErr == nil {
		t.Fatal("no error surfaced within 8 reads, want invalid padding")
	}
	if !errors.Is(firstErr, errInvalidBase64URLPadding) {
		t.Fatalf("first error = %v, want invalid padding", firstErr)
	}

	n, secondErr := reader.Read(buffer)
	if n != 0 {
		t.Fatalf("read after error = %d bytes, want 0", n)
	}
	if !errors.Is(secondErr, errInvalidBase64URLPadding) {
		t.Fatalf("second error = %v, want the same sticky invalid padding error", secondErr)
	}
}

type failingWriter struct {
	err error
}

func (writer failingWriter) Write([]byte) (int, error) {
	return 0, writer.err
}

func BenchmarkOutputEncodings(b *testing.B) {
	for _, name := range byteEncodingNames() {
		for _, size := range benchmarkEncodingSizes {
			b.Run(fmt.Sprintf("%s/%s", name, size.name), func(b *testing.B) {
				data := make([]byte, size.bytes)
				encoder, err := getOutputEncoder(name)
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
	for _, name := range byteEncodingNames() {
		for _, size := range benchmarkEncodingSizes {
			b.Run(fmt.Sprintf("%s/%s", name, size.name), func(b *testing.B) {
				encoded := encodeBenchmarkInput(b, name, make([]byte, size.bytes))
				decoder, err := getInputDecoder(name)
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
	encoder, err := getOutputEncoder(name)
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
