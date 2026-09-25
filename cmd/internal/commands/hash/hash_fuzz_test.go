package hash_test

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

const (
	fuzzHashCopyBufferSize = 32 << 10
	maxFuzzHashInputSize   = 2*fuzzHashCopyBufferSize + 1
)

var errInvalidHashBase64URLPadding = errors.New("invalid base64url padding")

func FuzzHashCommand(f *testing.F) {
	for _, seed := range []struct {
		wire           []byte
		algorithm      uint8
		inputEncoding  uint8
		outputEncoding uint8
		chunkSize      uint16
	}{
		{wire: nil},
		{wire: []byte("abc"), algorithm: 2, chunkSize: 1},
		{wire: []byte("00ff1080"), algorithm: 3, inputEncoding: 1, outputEncoding: 5, chunkSize: 63},
		{wire: []byte("YQ="), inputEncoding: 2, outputEncoding: 2},
		{wire: []byte("YQ==\r\n"), algorithm: 1, inputEncoding: 2, outputEncoding: 3, chunkSize: 2},
		{wire: []byte("MZXW6=="), inputEncoding: 5, outputEncoding: 4, chunkSize: 4},
		{wire: bytes.Repeat([]byte{0xa5}, 129), algorithm: 3, chunkSize: 127},
	} {
		f.Add(seed.wire, seed.algorithm, seed.inputEncoding, seed.outputEncoding, seed.chunkSize)
	}
	for _, size := range []int{
		fuzzHashCopyBufferSize - 1,
		fuzzHashCopyBufferSize,
		fuzzHashCopyBufferSize + 1,
		2*fuzzHashCopyBufferSize + 1,
	} {
		chunkSize := min(size, fuzzHashCopyBufferSize+1)
		f.Add(hashTestPayload(size), uint8(2), uint8(0), uint8(0), uint16(chunkSize-1))
	}

	algorithms := []string{"md5", "sha1", "sha256", "sha512"}
	encodings := []string{"raw", "hex", "base64", "b64", "base64url", "base32"}
	f.Fuzz(func(t *testing.T, wire []byte, algorithmSelector, inputSelector, outputSelector uint8, chunkSelector uint16) {
		if len(wire) > maxFuzzHashInputSize {
			t.Skip()
		}
		algorithm := algorithms[int(algorithmSelector)%len(algorithms)]
		inputEncoding := encodings[int(inputSelector)%len(encodings)]
		outputEncoding := encodings[int(outputSelector)%len(encodings)]
		chunkSize := int(chunkSelector)%(fuzzHashCopyBufferSize+1) + 1

		decoded, decodeErr := referenceHashInput(inputEncoding, wire, chunkSize == 1)
		output, err := executeHashCommand(
			t,
			newHashChunkReader(wire, chunkSize),
			"hash", algorithm,
			"--input-encoding", inputEncoding,
			"--encoding", outputEncoding,
		)
		if decodeErr != nil {
			if err == nil {
				t.Fatalf("%s input accepted malformed %s data %q", algorithm, inputEncoding, wire)
			}
			if len(output) != 0 {
				t.Fatalf("malformed input produced output %x", output)
			}
			return
		}
		if err != nil {
			t.Fatalf("valid %s input failed: %v", inputEncoding, err)
		}
		want := encodeHashDigest(algorithm, decoded, outputEncoding)
		if !bytes.Equal(output, want) {
			t.Fatalf(
				"%s digest with %s input/%s output = %x, want %x",
				algorithm,
				inputEncoding,
				outputEncoding,
				output,
				want,
			)
		}
	})
}

func referenceHashInput(name string, wire []byte, oneByte bool) ([]byte, error) {
	clean := bytes.Clone(wire)
	if name != "raw" {
		clean = bytes.ReplaceAll(clean, []byte{'\r'}, nil)
		clean = bytes.ReplaceAll(clean, []byte{'\n'}, nil)
	}
	if name == "base64" || name == "b64" {
		data, err := base64.StdEncoding.DecodeString(string(clean))
		if err != nil {
			return data, fmt.Errorf("decode reference %s input: %w", name, err)
		}
		return data, nil
	}
	if name == "base64url" {
		data, paddingErr := referenceHashBase64URLData(string(clean))
		decoded, err := base64.RawURLEncoding.DecodeString(data)
		if err = errors.Join(err, paddingErr); err != nil {
			return decoded, fmt.Errorf("decode reference %s input: %w", name, err)
		}
		return decoded, nil
	}
	var source io.Reader = bytes.NewReader(clean)
	if oneByte {
		source = iotest.OneByteReader(source)
	}
	var decoded io.Reader
	switch name {
	case "raw":
		decoded = source
	case "hex":
		decoded = hex.NewDecoder(source)
	case "base32":
		decoded = base32.NewDecoder(base32.StdEncoding, source)
	default:
		panic("unsupported test input encoding " + name)
	}
	data, err := io.ReadAll(decoded)
	if err != nil {
		return data, fmt.Errorf("decode reference %s input: %w", name, err)
	}
	return data, nil
}

func referenceHashBase64URLData(input string) (string, error) {
	paddingStart := strings.IndexByte(input, '=')
	if paddingStart < 0 {
		return input, nil
	}
	data := input[:paddingStart]
	padding := input[paddingStart:]
	if padding == "=" && len(data)%4 == 3 || padding == "==" && len(data)%4 == 2 {
		return data, nil
	}
	return data, errInvalidHashBase64URLPadding
}
