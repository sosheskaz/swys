package hash_test

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rootcmd "github.com/sosheskaz-systems/npc/cmd"
	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
)

var (
	errHashTestRead     = errors.New("hash test read failure")
	errHashTestWrite    = errors.New("hash test write failure")
	errHashTestFinalize = errors.New("hash test encoder finalization failure")
)

func TestHashKnownVectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		algorithm string
		input     string
		want      string
	}{
		{algorithm: "md5", input: "", want: "d41d8cd98f00b204e9800998ecf8427e\n"},
		{algorithm: "md5", input: "abc", want: "900150983cd24fb0d6963f7d28e17f72\n"},
		{algorithm: "sha1", input: "", want: "da39a3ee5e6b4b0d3255bfef95601890afd80709\n"},
		{algorithm: "sha1", input: "abc", want: "a9993e364706816aba3e25717850c26c9cd0d89d\n"},
		{algorithm: "sha256", input: "", want: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"},
		{algorithm: "sha256", input: "abc", want: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"},
		{
			algorithm: "sha512",
			input:     "",
			want: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
				"47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e\n",
		},
		{
			algorithm: "sha512",
			input:     "abc",
			want: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
				"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f\n",
		},
	}

	for _, test := range tests {
		t.Run(test.algorithm+"/"+fmt.Sprintf("%x", test.input), func(t *testing.T) {
			t.Parallel()
			output, err := executeHashCommand(t, strings.NewReader(test.input), "hash", test.algorithm)
			require.NoError(t, err)
			assert.Equal(t, test.want, string(output))
		})
	}
}

func TestHashOutputEncodingRegistry(t *testing.T) {
	t.Parallel()

	payload := []byte{0x00, 0xff, 0x10, 0x80, 'n', 'p', 'c'}
	digest := sha256.Sum256(payload)
	tests := []struct {
		name string
		want []byte
	}{
		{name: "raw", want: bytes.Clone(digest[:])},
		{name: "hex", want: []byte(hex.EncodeToString(digest[:]) + "\n")},
		{name: "base64", want: []byte(base64.StdEncoding.EncodeToString(digest[:]) + "\n")},
		{name: "b64", want: []byte(base64.StdEncoding.EncodeToString(digest[:]) + "\n")},
		{name: "base64url", want: []byte(base64.RawURLEncoding.EncodeToString(digest[:]) + "\n")},
		{name: "base32", want: []byte(base32.StdEncoding.EncodeToString(digest[:]) + "\n")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output, err := executeHashCommand(
				t,
				bytes.NewReader(payload),
				"hash", "sha256", "--encoding", test.name,
			)
			require.NoError(t, err)
			assert.Equal(t, test.want, output)
		})
	}
}

func TestHashRawDigestSizes(t *testing.T) {
	t.Parallel()

	for algorithm, size := range map[string]int{"md5": md5.Size, "sha1": sha1.Size, "sha256": sha256.Size, "sha512": sha512.Size} {
		t.Run(algorithm, func(t *testing.T) {
			t.Parallel()
			output, err := executeHashCommand(t, bytes.NewReader(nil), "hash", algorithm, "-e", "raw")
			require.NoError(t, err)
			assert.Len(t, output, size, "raw digest")
		})
	}
}

func TestHashInputEncodingRegistry(t *testing.T) {
	t.Parallel()

	payload := []byte("encoded input\x00\x80\xff")
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "raw", input: bytes.Clone(payload)},
		{name: "hex", input: []byte(hex.EncodeToString(payload))},
		{name: "base64", input: []byte(base64.StdEncoding.EncodeToString(payload))},
		{name: "b64", input: []byte(base64.StdEncoding.EncodeToString(payload))},
		{name: "base64url", input: []byte(base64.URLEncoding.EncodeToString(payload))},
		{name: "base32", input: []byte(base32.StdEncoding.EncodeToString(payload))},
	}
	digest := sha256.Sum256(payload)
	want := hex.EncodeToString(digest[:]) + "\n"

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output, err := executeHashCommand(
				t,
				newHashChunkReader(test.input, 1),
				"hash", "sha256", "--input-encoding", test.name,
			)
			require.NoError(t, err)
			assert.Equal(t, want, string(output))
		})
	}
}

func TestHashRawInputNewlineChangesDigest(t *testing.T) {
	t.Parallel()

	withoutNewline, err := executeHashCommand(t, strings.NewReader("abc"), "hash", "sha256")
	require.NoError(t, err)
	withNewline, err := executeHashCommand(t, strings.NewReader("abc\n"), "hash", "sha256")
	require.NoError(t, err)
	assert.NotEqual(t, withoutNewline, withNewline, "raw input newline did not change digest")
	const wantWithNewline = "edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb\n"
	assert.Equal(t, wantWithNewline, string(withNewline), "newline digest")
}

func TestHashBareCommandShowsAlgorithmHelp(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "output")
	const original = "preserve without an explicit algorithm"
	require.NoError(t, os.WriteFile(path, []byte(original), 0o600))
	output, err := executeHashCommand(t, hashPanicReader{}, "hash", "--output", path)
	require.NoError(t, err)
	help := string(output)
	for _, text := range []string{"Usage:", "sha256", "sha512", "sha1", "md5"} {
		assert.Contains(t, help, text, "bare hash help")
	}
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, original, string(contents), "bare hash command changed output")
}

func TestHashCompatibilityAlgorithmsSaySoInHelp(t *testing.T) {
	t.Parallel()

	for _, algorithm := range []string{"md5", "sha1"} {
		t.Run(algorithm, func(t *testing.T) {
			t.Parallel()
			output, err := executeHashCommand(t, bytes.NewReader(nil), "hash", algorithm, "--help")
			require.NoError(t, err)
			assert.Contains(t, strings.ToLower(string(output)), "compatib", "%s help", algorithm)
		})
	}
}

func TestHashRejectsOperands(t *testing.T) {
	t.Parallel()

	for _, algorithm := range []string{"sha256", "sha512", "sha1", "md5"} {
		t.Run(algorithm, func(t *testing.T) {
			t.Parallel()
			output, err := executeHashCommand(t, strings.NewReader("stdin"), "hash", algorithm, "operand")
			require.Error(t, err, "command accepted an operand, want stdin/--input only")
			assert.Empty(t, output, "failed command output")
		})
	}
}

func TestHashInputOutputFlagsAndShorthands(t *testing.T) {
	t.Parallel()

	for _, flags := range []struct {
		name   string
		input  string
		output string
	}{
		{name: "long", input: "--input", output: "--output"},
		{name: "short", input: "-i", output: "-o"},
	} {
		t.Run(flags.name, func(t *testing.T) {
			t.Parallel()
			directory := t.TempDir()
			inputPath := filepath.Join(directory, "input")
			outputPath := filepath.Join(directory, "output")
			require.NoError(t, os.WriteFile(inputPath, []byte("flag input"), 0o600))
			stdout, err := executeHashCommand(
				t,
				strings.NewReader("ignored stdin"),
				"hash", "sha512", flags.input, inputPath, flags.output, outputPath,
			)
			require.NoError(t, err)
			assert.Empty(t, stdout, "redirected output")
			output, err := os.ReadFile(outputPath)
			require.NoError(t, err)
			want := encodeHashDigest("sha512", []byte("flag input"), "hex")
			assert.Equal(t, want, output, "output file")
		})
	}
}

func TestHashStreamingBoundaries(t *testing.T) {
	t.Parallel()

	const copyBufferSize = 32 << 10
	tests := []struct {
		algorithm string
		sizes     []int
	}{
		{algorithm: "md5", sizes: []int{0, 1, md5.BlockSize - 1, md5.BlockSize, md5.BlockSize + 1}},
		{algorithm: "sha1", sizes: []int{sha1.BlockSize - 1, sha1.BlockSize, sha1.BlockSize + 1}},
		{algorithm: "sha256", sizes: []int{copyBufferSize - 1, copyBufferSize, copyBufferSize + 1, 2*copyBufferSize + 17}},
		{algorithm: "sha512", sizes: []int{sha512.BlockSize - 1, sha512.BlockSize, sha512.BlockSize + 1}},
	}

	for _, test := range tests {
		for _, size := range test.sizes {
			name := fmt.Sprintf("%s/%d", test.algorithm, size)
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				payload := hashTestPayload(size)
				for _, chunkSize := range []int{1, 97} {
					output, err := executeHashCommand(
						t,
						newHashChunkReader(payload, chunkSize),
						"hash", test.algorithm,
					)
					require.NoError(t, err)
					want := encodeHashDigest(test.algorithm, payload, "hex")
					assert.Equal(t, want, output, "chunk %d", chunkSize)
				}
			})
		}
	}
}

func TestHashInputFailuresPreserveExistingOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input io.Reader
		isErr error
		args  []string
	}{
		{
			name:  "malformed hex",
			input: strings.NewReader("00fg"),
			args:  []string{"hash", "sha256", "--input-encoding", "hex"},
		},
		{
			name:  "truncated base64",
			input: strings.NewReader("YQ="),
			args:  []string{"hash", "sha256", "--input-encoding", "base64"},
		},
		{
			name:  "error with data",
			input: &hashDataErrorReader{data: []byte("partial")},
			args:  []string{"hash", "sha256"},
			isErr: errHashTestRead,
		},
		{
			name:  "unknown input encoding",
			input: strings.NewReader("data"),
			args:  []string{"hash", "sha256", "--input-encoding", "rot13"},
		},
		{
			name:  "unknown output encoding",
			input: strings.NewReader("data"),
			args:  []string{"hash", "sha256", "--encoding", "rot13"},
		},
		{
			name:  "unknown algorithm",
			input: strings.NewReader("data"),
			args:  []string{"hash", "sha999"},
		},
		{
			name:  "unexpected operand",
			input: strings.NewReader("data"),
			args:  []string{"hash", "sha256", "operand"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "output")
			const original = "preserve existing output"
			require.NoError(t, os.WriteFile(path, []byte(original), 0o600))
			args := append(append([]string(nil), test.args...), "--output", path)
			output, err := executeHashCommand(t, test.input, args...)
			require.Error(t, err, "command succeeded, want input/encoding error")
			if test.isErr != nil {
				require.ErrorIs(t, err, test.isErr)
			}
			assert.Empty(t, output, "stdout after failed command")
			contents, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			assert.Equal(t, original, string(contents), "output file after failed command")
		})
	}
}

func TestHashMissingInputPreservesExistingOutput(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	inputPath := filepath.Join(directory, "missing")
	outputPath := filepath.Join(directory, "output")
	const original = "preserve existing output"
	require.NoError(t, os.WriteFile(outputPath, []byte(original), 0o600))
	_, err := executeHashCommand(
		t,
		bytes.NewReader(nil),
		"hash", "sha256", "--input", inputPath, "--output", outputPath,
	)
	require.ErrorIs(t, err, os.ErrNotExist)
	contents, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	assert.Equal(t, original, string(contents), "output file after missing input")
}

func TestHashReportsOutputWriteFailure(t *testing.T) {
	t.Parallel()

	err := runHashCommand(t, strings.NewReader("payload"), hashFailingWriter{err: errHashTestWrite}, "hash", "sha256")
	assert.ErrorIs(t, err, errHashTestWrite)
}

func TestHashReportsShortWrites(t *testing.T) {
	t.Parallel()

	t.Run("raw digest", func(t *testing.T) {
		t.Parallel()
		err := runHashCommand(t, strings.NewReader("payload"), hashShortDigestWriter{}, "hash", "sha256", "--encoding", "raw")
		require.ErrorIs(t, err, io.ErrShortWrite)
	})

	t.Run("text newline", func(t *testing.T) {
		t.Parallel()
		output := &hashShortNewlineWriter{}
		err := runHashCommand(t, strings.NewReader("payload"), output, "hash", "sha256")
		require.ErrorIs(t, err, io.ErrShortWrite)
		if bytes.HasSuffix(output.data, []byte{'\n'}) {
			t.Fatalf("short newline write unexpectedly produced complete text output %q", output.data)
		}
	})

	t.Run("base64 encoded digest", func(t *testing.T) {
		t.Parallel()
		output := &hashShortFirstEncodedWriter{}
		err := runHashCommand(t, strings.NewReader("payload"), output, "hash", "sha256", "--encoding", "base64")
		require.ErrorIs(t, err, io.ErrShortWrite)
		assert.True(t, output.shortened, "writer did not observe an encoded digest group")
	})

	t.Run("base32 final padded group", func(t *testing.T) {
		t.Parallel()
		output := &hashShortPaddingWriter{}
		err := runHashCommand(t, strings.NewReader("payload"), output, "hash", "sha256", "--encoding", "base32")
		require.ErrorIs(t, err, io.ErrShortWrite)
		assert.True(t, output.shortened, "writer did not observe the final padded group")
		if bytes.HasSuffix(output.data, []byte{'\n'}) {
			t.Fatalf("short encoder finalization unexpectedly wrote a newline: %q", output.data)
		}
	})
}

func TestHashReportsEncoderFinalizationFailureBeforeTextNewline(t *testing.T) {
	t.Parallel()

	output := &hashPaddingFailWriter{}
	err := runHashCommand(t, strings.NewReader("payload"), output, "hash", "sha256", "--encoding", "base32")
	require.ErrorIs(t, err, errHashTestFinalize)
	assert.NotEmpty(t, output.data, "encoder wrote no complete groups before its final padded group")
	if bytes.ContainsAny(output.data, "=\n") {
		t.Fatalf("failed finalization output = %q, want only complete unpadded groups and no newline", output.data)
	}
}

func executeHashCommand(tb testing.TB, input io.Reader, args ...string) ([]byte, error) {
	tb.Helper()
	var output bytes.Buffer
	err := runHashCommand(tb, input, &output, args...)
	return output.Bytes(), err
}

func runHashCommand(tb testing.TB, input io.Reader, output io.Writer, args ...string) error {
	tb.Helper()
	root := rootcmd.NewCommand()
	return testcmd.Run(tb, root, input, output, io.Discard, args...)
}

func hashDigest(algorithm string, data []byte) []byte {
	switch algorithm {
	case "md5":
		digest := md5.Sum(data)
		return digest[:]
	case "sha1":
		digest := sha1.Sum(data)
		return digest[:]
	case "sha256":
		digest := sha256.Sum256(data)
		return digest[:]
	case "sha512":
		digest := sha512.Sum512(data)
		return digest[:]
	default:
		panic("unsupported test hash algorithm " + algorithm)
	}
}

func encodeHashDigest(algorithm string, data []byte, encoding string) []byte {
	digest := hashDigest(algorithm, data)
	switch encoding {
	case "raw":
		return bytes.Clone(digest)
	case "hex":
		return []byte(hex.EncodeToString(digest) + "\n")
	case "base64", "b64":
		return []byte(base64.StdEncoding.EncodeToString(digest) + "\n")
	case "base64url":
		return []byte(base64.RawURLEncoding.EncodeToString(digest) + "\n")
	case "base32":
		return []byte(base32.StdEncoding.EncodeToString(digest) + "\n")
	default:
		panic("unsupported test encoding " + encoding)
	}
}

func hashTestPayload(size int) []byte {
	payload := make([]byte, size)
	for index := range payload {
		payload[index] = byte(index*31 + 17)
	}
	return payload
}

type hashChunkReader struct {
	source    *bytes.Reader
	chunkSize int
}

func newHashChunkReader(data []byte, chunkSize int) *hashChunkReader {
	return &hashChunkReader{source: bytes.NewReader(data), chunkSize: chunkSize}
}

func (reader *hashChunkReader) Read(buffer []byte) (int, error) {
	if len(buffer) > reader.chunkSize {
		buffer = buffer[:reader.chunkSize]
	}
	return reader.source.Read(buffer) //nolint:wrapcheck // preserve io.EOF identity in a test reader
}

type hashDataErrorReader struct {
	data []byte
	done bool
}

type hashPanicReader struct{}

func (hashPanicReader) Read([]byte) (int, error) {
	panic("bare hash command read stdin")
}

func (reader *hashDataErrorReader) Read(buffer []byte) (int, error) {
	if reader.done {
		return 0, errHashTestRead
	}
	reader.done = true
	read := copy(buffer, reader.data)
	return read, errHashTestRead
}

type hashFailingWriter struct {
	err error
}

func (writer hashFailingWriter) Write([]byte) (int, error) {
	return 0, writer.err
}

type hashShortDigestWriter struct{}

func (hashShortDigestWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	return len(data) - 1, nil
}

type hashShortNewlineWriter struct {
	data []byte
}

func (writer *hashShortNewlineWriter) Write(data []byte) (int, error) {
	if bytes.Equal(data, []byte{'\n'}) {
		return 0, nil
	}
	writer.data = append(writer.data, data...)
	return len(data), nil
}

type hashShortFirstEncodedWriter struct {
	data      []byte
	shortened bool
}

func (writer *hashShortFirstEncodedWriter) Write(data []byte) (int, error) {
	if !writer.shortened && len(data) > 1 && !bytes.Equal(data, []byte{'\n'}) {
		writer.shortened = true
		writer.data = append(writer.data, data[:len(data)-1]...)
		return len(data) - 1, nil
	}
	writer.data = append(writer.data, data...)
	return len(data), nil
}

type hashShortPaddingWriter struct {
	data      []byte
	shortened bool
}

func (writer *hashShortPaddingWriter) Write(data []byte) (int, error) {
	if !writer.shortened && bytes.ContainsRune(data, '=') {
		writer.shortened = true
		writer.data = append(writer.data, data[:len(data)-1]...)
		return len(data) - 1, nil
	}
	writer.data = append(writer.data, data...)
	return len(data), nil
}

type hashPaddingFailWriter struct {
	data []byte
}

func (writer *hashPaddingFailWriter) Write(data []byte) (int, error) {
	if bytes.ContainsRune(data, '=') {
		return 0, errHashTestFinalize
	}
	writer.data = append(writer.data, data...)
	return len(data), nil
}
