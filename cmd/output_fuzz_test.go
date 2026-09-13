package cmd

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

const maxFuzzByteEncodingInputSize = 1 << 12

var (
	errFuzzEncodedInputRead        = errors.New("fuzz encoded input read failure")
	errFuzzInvalidBase64URLPadding = errors.New("fuzz invalid base64url padding")
)

type fuzzByteEncodingReference struct {
	encode        func([]byte) []byte
	decode        func(io.Reader) io.Reader
	stripNewlines bool
}

var fuzzByteEncodingReferences = map[string]fuzzByteEncodingReference{
	"raw": {
		encode: bytes.Clone,
		decode: func(source io.Reader) io.Reader { return source },
	},
	"hex": {
		encode:        func(data []byte) []byte { return []byte(hex.EncodeToString(data)) },
		decode:        hex.NewDecoder,
		stripNewlines: true,
	},
	"base64": {
		encode: func(data []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(data)) },
		decode: func(source io.Reader) io.Reader {
			return base64.NewDecoder(base64.StdEncoding, source)
		},
		stripNewlines: true,
	},
	"base64url": {
		encode: func(data []byte) []byte { return []byte(base64.RawURLEncoding.EncodeToString(data)) },
		decode: func(source io.Reader) io.Reader {
			return base64.NewDecoder(base64.RawURLEncoding, source)
		},
		stripNewlines: true,
	},
	"base32": {
		encode: func(data []byte) []byte { return []byte(base32.StdEncoding.EncodeToString(data)) },
		decode: func(source io.Reader) io.Reader {
			return base32.NewDecoder(base32.StdEncoding, source)
		},
		stripNewlines: true,
	},
}

var fuzzByteEncodingAliases = map[string]string{"b64": "base64"}

func FuzzBase64URLDecoder(f *testing.F) {
	for _, seed := range []string{"", "Zg", "Zg==", "Zm8=", "Zm9v", "Zg=", "Z===", "Zm\r\n8=", "Zm8=A", "_w=="} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxFuzzByteEncodingInputSize {
			t.Skip()
		}
		clean := strings.NewReplacer("\r", "", "\n", "").Replace(input)
		encoding := base64.RawURLEncoding
		if strings.Contains(clean, "=") {
			encoding = base64.URLEncoding
		}
		want, wantErr := encoding.DecodeString(clean)
		for _, reader := range []io.Reader{strings.NewReader(input), iotest.OneByteReader(strings.NewReader(input))} {
			got, err := io.ReadAll(base64URLDecoder(reader))
			if (err == nil) != (wantErr == nil) {
				t.Fatalf("acceptance differs from stdlib: got %v, want %v", err, wantErr)
			}
			if err == nil && !bytes.Equal(got, want) {
				t.Fatalf("decoded bytes differ: got %x, want %x", got, want)
			}
		}
	})
}

func FuzzByteEncodingRoundTrip(f *testing.F) {
	for _, seed := range []struct {
		data           []byte
		writeChunkSize uint8
		lineWidth      uint8
	}{
		{data: nil, writeChunkSize: 0, lineWidth: 0},
		{data: []byte("f"), writeChunkSize: 0, lineWidth: 29},
		{data: []byte("fo"), writeChunkSize: 29, lineWidth: 0},
		{data: []byte("arbitrary\x00\x80\xffbytes"), writeChunkSize: 6, lineWidth: 17},
		{data: bytes.Repeat([]byte{0xa5}, 65), writeChunkSize: 30, lineWidth: 12},
	} {
		f.Add(seed.data, seed.writeChunkSize, seed.lineWidth)
	}

	names := registeredFuzzByteEncodingNames(f)
	f.Fuzz(func(t *testing.T, data []byte, fuzzWriteChunkSize, fuzzLineWidth uint8) {
		if len(data) > maxFuzzByteEncodingInputSize {
			t.Skip()
		}
		writeChunkSize := int(fuzzWriteChunkSize)%31 + 1
		lineWidth := int(fuzzLineWidth)%31 + 1
		for _, name := range names {
			checkByteEncodingRoundTrip(t, name, data, writeChunkSize, lineWidth)
		}
	})
}

func checkByteEncodingRoundTrip(t *testing.T, name string, data []byte, writeChunkSize, lineWidth int) {
	t.Helper()
	encoder, err := getOutputEncoder(name)
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	writer, closer := encoder(&encoded)
	for offset := 0; offset < len(data); {
		end := min(offset+writeChunkSize, len(data))
		written, writeErr := writer.Write(data[offset:end])
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		if written != end-offset {
			t.Fatal(io.ErrShortWrite)
		}
		offset = end
	}
	if closer != nil {
		if err := closer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	wantEncoded := referenceEncode(t, name, data)
	if !bytes.Equal(encoded.Bytes(), wantEncoded) {
		t.Fatalf("%s encoding = %q, want %q", name, encoded.Bytes(), wantEncoded)
	}

	wire := encoded.Bytes()
	if name != "raw" {
		wire = wrapEncodedLines(wire, lineWidth)
	}
	decoder, err := getInputDecoder(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, oneByte := range []bool{false, true} {
		var reader io.Reader = bytes.NewReader(wire)
		if oneByte {
			reader = iotest.OneByteReader(reader)
		}
		decoded, decodeErr := io.ReadAll(decoder(reader))
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if !bytes.Equal(decoded, data) {
			t.Fatalf("%s round trip changed bytes: got %x, want %x", name, decoded, data)
		}
	}
}

func FuzzByteDecoders(f *testing.F) {
	for _, seed := range []string{"", "0", "00", "Zg==", "Zg=", "MZXW6===", "MZXW6=="} {
		f.Add(seed)
	}

	names := registeredFuzzByteEncodingNames(f)
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxFuzzByteEncodingInputSize {
			t.Skip()
		}
		for _, name := range names {
			decoder, err := getInputDecoder(name)
			if err != nil {
				t.Fatal(err)
			}
			for _, oneByte := range []bool{false, true} {
				var reader io.Reader = strings.NewReader(input)
				if oneByte {
					reader = iotest.OneByteReader(reader)
				}
				got, decodeErr := io.ReadAll(decoder(reader))
				want, wantErr := referenceStreamingDecode(t, name, input, oneByte)
				if (decodeErr == nil) != (wantErr == nil) {
					t.Fatalf("%s acceptance differs from standard decoder: got %v, want %v", name, decodeErr, wantErr)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("%s decoded prefix = %x, want %x", name, got, want)
				}
			}
		}
	})
}

func FuzzStripNewlinesInputFailure(f *testing.F) {
	f.Add([]byte{}, uint16(0), uint8(1))
	f.Add([]byte("\r\n"), uint16(2), uint8(1))
	f.Add([]byte("a\r\nb\nc"), uint16(4), uint8(2))
	f.Add([]byte{0x00, '\n', 0x80, '\r', 0xff}, uint16(5), uint8(3))

	f.Fuzz(func(t *testing.T, data []byte, fuzzFailure uint16, fuzzChunkSize uint8) {
		if len(data) > maxFuzzByteEncodingInputSize {
			t.Skip()
		}
		failAfter := 0
		if len(data) > 0 {
			failAfter = int(fuzzFailure) % (len(data) + 1)
		}
		source := &fuzzEncodedInputFailingReader{
			data:      data,
			failAfter: failAfter,
			chunkSize: int(fuzzChunkSize)%31 + 1,
		}
		got, err := io.ReadAll(stripNewlines(source))
		if !errors.Is(err, errFuzzEncodedInputRead) {
			t.Fatalf("read error = %v, want injected error", err)
		}
		want := bytes.ReplaceAll(bytes.Clone(data[:failAfter]), []byte{'\r'}, nil)
		want = bytes.ReplaceAll(want, []byte{'\n'}, nil)
		if !bytes.Equal(got, want) {
			t.Fatalf("filtered prefix = %x, want %x", got, want)
		}
		if source.position != failAfter {
			t.Fatalf("source consumed %d bytes, want %d", source.position, failAfter)
		}
	})
}

func registeredFuzzByteEncodingNames(f *testing.F) []string {
	f.Helper()
	registered := byteEncodingNames()
	registeredSet := make(map[string]struct{}, len(registered))
	for _, name := range registered {
		registeredSet[name] = struct{}{}
	}

	seen := make(map[string]struct{}, len(registered))
	names := make([]string, 0, len(registered))
	for _, name := range registered {
		canonical := name
		if alias, ok := fuzzByteEncodingAliases[name]; ok {
			canonical = alias
		}
		if _, ok := fuzzByteEncodingReferences[canonical]; !ok {
			f.Fatalf("registered byte encoding %q has no independent fuzz reference", name)
		}
		if _, ok := registeredSet[canonical]; !ok {
			f.Fatalf("registered byte encoding alias %q names missing canonical encoding %q", name, canonical)
		}
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		names = append(names, canonical)
	}
	return names
}

func referenceEncode(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	reference, ok := fuzzByteEncodingReferences[name]
	if !ok {
		t.Fatalf("registered byte encoding %q has no independent output reference", name)
	}
	return reference.encode(data)
}

func referenceStreamingDecode(t *testing.T, name, input string, oneByte bool) ([]byte, error) {
	t.Helper()
	reference, ok := fuzzByteEncodingReferences[name]
	if !ok {
		t.Fatalf("registered byte encoding %q has no independent decoder reference", name)
	}
	if reference.stripNewlines {
		input = strings.NewReplacer("\r", "", "\n", "").Replace(input)
	}
	var paddingErr error
	if name == "base64url" {
		input, paddingErr = referenceBase64URLData(input)
	}
	var source io.Reader = strings.NewReader(input)
	if oneByte {
		source = iotest.OneByteReader(source)
	}
	reader := reference.decode(source)
	decoded, err := io.ReadAll(reader)
	err = errors.Join(err, paddingErr)
	if err != nil {
		return decoded, fmt.Errorf("decode reference %s: %w", name, err)
	}
	return decoded, nil
}

func referenceBase64URLData(input string) (string, error) {
	paddingStart := strings.IndexByte(input, '=')
	if paddingStart < 0 {
		return input, nil
	}
	data := input[:paddingStart]
	padding := input[paddingStart:]
	validSinglePadding := padding == "=" && len(data)%4 == 3
	validDoublePadding := padding == "==" && len(data)%4 == 2
	if validSinglePadding || validDoublePadding {
		return data, nil
	}
	return data, errFuzzInvalidBase64URLPadding
}

func wrapEncodedLines(data []byte, width int) []byte {
	var wrapped bytes.Buffer
	for offset := 0; offset < len(data); {
		end := min(offset+width, len(data))
		wrapped.Write(data[offset:end])
		offset = end
		if offset < len(data) {
			wrapped.WriteString("\r\n")
		}
	}
	return wrapped.Bytes()
}

type fuzzEncodedInputFailingReader struct {
	data      []byte
	position  int
	failAfter int
	chunkSize int
}

func (reader *fuzzEncodedInputFailingReader) Read(buffer []byte) (int, error) {
	if reader.position >= reader.failAfter {
		return 0, errFuzzEncodedInputRead
	}
	end := min(reader.failAfter, reader.position+len(buffer), reader.position+reader.chunkSize)
	read := copy(buffer, reader.data[reader.position:end])
	reader.position += read
	if reader.position == reader.failAfter {
		return read, errFuzzEncodedInputRead
	}
	return read, nil
}
