package crypter

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

var errInvalidGCMVector = errors.New("invalid GCM vector fixture")

func TestNISTGCMFixturesHaveCanonicalWhitespace(t *testing.T) {
	t.Parallel()

	paths, err := filepath.Glob(filepath.Join("testdata", "nist-gcm", "*.rsp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 6 {
		t.Fatalf("fixtures = %d, want 6", len(paths))
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for index, line := range bytes.Split(data, []byte("\n")) {
				if !bytes.Equal(line, bytes.TrimRight(line, " \t\r")) {
					t.Errorf("line %d has trailing whitespace; empty fields must use FIELD =", index+1)
					break
				}
			}
			if !bytes.HasSuffix(data, []byte("\n")) {
				t.Error("fixture does not end with a newline")
			} else if bytes.HasSuffix(data, []byte("\n\n")) {
				t.Error("fixture has an extra final blank line")
			}
		})
	}
}

func TestAESGCMNISTCAVPVectors(t *testing.T) {
	t.Parallel()

	type fixture struct {
		name       string
		decrypt    bool
		keyBytes   int
		wantPasses int
	}
	fixtures := []fixture{
		{name: "gcmEncryptExtIV128.rsp", keyBytes: 16, wantPasses: 375},
		{name: "gcmEncryptExtIV192.rsp", keyBytes: 24, wantPasses: 375},
		{name: "gcmEncryptExtIV256.rsp", keyBytes: 32, wantPasses: 375},
		{name: "gcmDecrypt128.rsp", decrypt: true, keyBytes: 16, wantPasses: 179},
		{name: "gcmDecrypt192.rsp", decrypt: true, keyBytes: 24, wantPasses: 185},
		{name: "gcmDecrypt256.rsp", decrypt: true, keyBytes: 32, wantPasses: 184},
	}

	var total atomic.Int64
	t.Cleanup(func() {
		if got := total.Load(); got != 2250 {
			t.Fatalf("total vectors = %d, want 2250", got)
		}
	})
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join("testdata", "nist-gcm", fixture.name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			vectors, err := parseGCMVectors(bytes.NewReader(data), fixture.decrypt)
			if err != nil {
				t.Fatal(err)
			}
			if len(vectors) != 375 {
				t.Fatalf("vectors = %d, want 375", len(vectors))
			}
			passes := 0
			for index, vector := range vectors {
				if len(vector.key) != fixture.keyBytes {
					t.Fatalf("vector %d key bytes = %d, want %d", index, len(vector.key), fixture.keyBytes)
				}
				if !vector.fail {
					passes++
				}
				runGCMVector(t, fixture.decrypt, index, &vector)
			}
			if passes != fixture.wantPasses {
				t.Fatalf("passing vectors = %d, want %d", passes, fixture.wantPasses)
			}
			total.Add(int64(len(vectors)))
		})
	}
}

func TestParseGCMVectorsAcceptsCanonicalEmptyFields(t *testing.T) {
	t.Parallel()

	input := strings.Join([]string{
		"[Keylen = 128]",
		"[IVlen = 96]",
		"[PTlen = 0]",
		"[AADlen = 0]",
		"[Taglen = 128]",
		"",
		"Count = 0",
		"Key = 00000000000000000000000000000000",
		"IV = 000000000000000000000000",
		"PT =",
		"AAD =",
		"CT =",
		"Tag = 00000000000000000000000000000000",
		"",
	}, "\n")
	vectors, err := parseGCMVectors(strings.NewReader(input), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 1 {
		t.Fatalf("vectors = %d, want 1", len(vectors))
	}
	vector := vectors[0]
	if len(vector.pt) != 0 || len(vector.aad) != 0 || len(vector.ct) != 0 {
		t.Fatalf("empty field lengths = PT %d, AAD %d, CT %d", len(vector.pt), len(vector.aad), len(vector.ct))
	}
}

func TestParseGCMVectorsRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	validHeaders := "[Keylen = 128]\n[IVlen = 96]\n[PTlen = 0]\n[AADlen = 0]\n[Taglen = 128]\n\n"
	validRecord := strings.Join([]string{
		"Count = 0",
		"Key = 00000000000000000000000000000000",
		"IV = 000000000000000000000000",
		"PT = ",
		"AAD = ",
		"CT = ",
		"Tag = 00000000000000000000000000000000",
		"",
	}, "\n")
	tests := []struct {
		name  string
		input string
	}{
		{name: "unknown_header", input: strings.Replace(validHeaders, "[IVlen = 96]", "[Wat = 96]", 1) + validRecord},
		{name: "duplicate_header", input: validHeaders + "[Taglen = 128]\n" + validRecord},
		{name: "malformed_header", input: strings.Replace(validHeaders, "[IVlen = 96]", "[IVlen: 96]", 1) + validRecord},
		{name: "unsupported_iv", input: strings.Replace(validHeaders, "[IVlen = 96]", "[IVlen = 64]", 1) + validRecord},
		{name: "unsupported_tag", input: strings.Replace(validHeaders, "[Taglen = 128]", "[Taglen = 96]", 1) + validRecord},
		{name: "unknown_field", input: validHeaders + validRecord + "Wat = 00\n"},
		{name: "duplicate_field", input: validHeaders + strings.Replace(validRecord, "IV = ", "IV = 000000000000000000000000\nIV = ", 1)},
		{name: "malformed_field", input: validHeaders + strings.Replace(validRecord, "Key = ", "Key: ", 1)},
		{name: "malformed_empty_field", input: validHeaders + strings.Replace(validRecord, "PT = ", "PT", 1)},
		{name: "invalid_hex", input: validHeaders + strings.Replace(validRecord, "Key = 0", "Key = z", 1)},
		{name: "wrong_length", input: validHeaders + strings.Replace(validRecord, "IV = 000000000000000000000000", "IV = 00", 1)},
		{name: "incomplete_record", input: validHeaders + strings.Replace(validRecord, "Tag = 00000000000000000000000000000000\n", "", 1)},
		{name: "fail_with_plaintext", input: validHeaders + validRecord + "FAIL\n"},
		{name: "record_before_headers", input: validRecord},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := parseGCMVectors(strings.NewReader(tt.input), false); err == nil {
				t.Fatal("parser accepted invalid input")
			}
		})
	}
}

type gcmVector struct {
	key   []byte
	iv    []byte
	pt    []byte
	aad   []byte
	ct    []byte
	tag   []byte
	count int
	fail  bool
}

func runGCMVector(t *testing.T, decrypt bool, index int, vector *gcmVector) {
	t.Helper()
	crypter := newFixedNonceCrypterWithNonce(t, vector.key, maxGCMPlaintextSize, vector.iv)
	wire := make([]byte, 0, len(vector.iv)+len(vector.ct)+len(vector.tag))
	wire = append(wire, vector.iv...)
	wire = append(wire, vector.ct...)
	wire = append(wire, vector.tag...)

	if !decrypt {
		var output bytes.Buffer
		if err := crypter.Encrypt(bytes.NewReader(vector.pt), &output, vector.aad); err != nil {
			t.Fatalf("vector %d Count %d: Encrypt: %v", index, vector.count, err)
		}
		if !bytes.Equal(output.Bytes(), wire) {
			t.Fatalf("vector %d Count %d: ciphertext mismatch", index, vector.count)
		}
		return
	}

	var output countingWriter
	err := crypter.Decrypt(bytes.NewReader(wire), &output, vector.aad)
	if vector.fail {
		if !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("vector %d Count %d: error = %v, want authentication failure", index, vector.count, err)
		}
		assertNoWrites(t, &output)
		return
	}
	if err != nil {
		t.Fatalf("vector %d Count %d: Decrypt: %v", index, vector.count, err)
	}
	if output.calls != 1 || !bytes.Equal(output.data, vector.pt) {
		t.Fatalf("vector %d Count %d: plaintext mismatch or calls = %d", index, vector.count, output.calls)
	}
}

func parseGCMVectors(reader io.Reader, decrypt bool) ([]gcmVector, error) {
	scanner := bufio.NewScanner(reader)
	lineNumber := 0
	headers := map[string]int{}
	fields := map[string]string{}
	var vectors []gcmVector

	finishRecord := func(fail bool) error {
		if len(fields) == 0 {
			return nil
		}
		required := []string{"Count", "Key", "IV", "PT", "AAD", "CT", "Tag"}
		if decrypt && fail {
			required = []string{"Count", "Key", "IV", "AAD", "CT", "Tag"}
		}
		for _, name := range required {
			if _, ok := fields[name]; !ok {
				return invalidGCMVectorf("incomplete vector: missing %s", name)
			}
		}
		if len(fields) != len(required) {
			return invalidGCMVectorf("vector has unexpected fields")
		}
		count, err := strconv.Atoi(fields["Count"])
		if err != nil || count < 0 {
			return invalidGCMVectorf("invalid Count %q", fields["Count"])
		}
		decode := func(name string) ([]byte, error) {
			value, err := hex.DecodeString(fields[name])
			if err != nil {
				return nil, fmt.Errorf("invalid %s: %w", name, err)
			}
			return value, nil
		}
		key, err := decode("Key")
		if err != nil {
			return err
		}
		iv, err := decode("IV")
		if err != nil {
			return err
		}
		pt, err := decode("PT")
		if err != nil && (!decrypt || !fail) {
			return err
		}
		aad, err := decode("AAD")
		if err != nil {
			return err
		}
		ct, err := decode("CT")
		if err != nil {
			return err
		}
		tag, err := decode("Tag")
		if err != nil {
			return err
		}
		if !gcmVectorLengthsMatch(headers, key, iv, pt, aad, ct, tag, fail) {
			return invalidGCMVectorf("field length does not match section headers")
		}
		vectors = append(vectors, gcmVector{count: count, key: key, iv: iv, pt: pt, aad: aad, ct: ct, tag: tag, fail: fail})
		fields = map[string]string{}
		return nil
	}

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "FAIL" {
			if !decrypt {
				return nil, invalidGCMVectorf("line %d: FAIL in encrypt vectors", lineNumber)
			}
			if err := finishRecord(true); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNumber, err)
			}
			continue
		}
		if strings.HasPrefix(line, "[") {
			if len(fields) != 0 {
				if err := finishRecord(false); err != nil {
					return nil, fmt.Errorf("line %d: %w", lineNumber, err)
				}
			}
			var err error
			headers, err = parseGCMVectorHeader(line, lineNumber, headers)
			if err != nil {
				return nil, err
			}
			continue
		}

		if len(headers) != 5 {
			return nil, invalidGCMVectorf("line %d: vector before complete headers", lineNumber)
		}
		name, value, ok := strings.Cut(line, " =")
		if !ok || (value != "" && !strings.HasPrefix(value, " ")) {
			return nil, invalidGCMVectorf("line %d: malformed field", lineNumber)
		}
		value = strings.TrimPrefix(value, " ")
		allowed := map[string]bool{"Count": true, "Key": true, "IV": true, "PT": true, "AAD": true, "CT": true, "Tag": true}
		if !allowed[name] {
			return nil, invalidGCMVectorf("line %d: unknown field %q", lineNumber, name)
		}
		if name == "Count" && len(fields) != 0 {
			if err := finishRecord(false); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNumber, err)
			}
		}
		if _, exists := fields[name]; exists {
			return nil, invalidGCMVectorf("line %d: duplicate field %q", lineNumber, name)
		}
		fields[name] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan GCM vectors: %w", err)
	}
	if err := finishRecord(false); err != nil {
		return nil, fmt.Errorf("end of input: %w", err)
	}
	if len(headers) != 5 || len(vectors) == 0 {
		return nil, invalidGCMVectorf("no complete vectors")
	}
	return vectors, nil
}

func parseGCMVectorHeader(line string, lineNumber int, headers map[string]int) (map[string]int, error) {
	if !strings.HasSuffix(line, "]") {
		return nil, invalidGCMVectorf("line %d: malformed header", lineNumber)
	}
	name, value, ok := strings.Cut(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"), " = ")
	if !ok {
		return nil, invalidGCMVectorf("line %d: malformed header", lineNumber)
	}
	allowed := map[string]bool{"Keylen": true, "IVlen": true, "PTlen": true, "AADlen": true, "Taglen": true}
	if !allowed[name] {
		return nil, invalidGCMVectorf("line %d: unknown header %q", lineNumber, name)
	}
	if name == "Keylen" {
		if len(headers) != 0 && len(headers) != 5 {
			return nil, invalidGCMVectorf("line %d: incomplete section headers", lineNumber)
		}
		headers = map[string]int{}
	} else if len(headers) == 0 {
		return nil, invalidGCMVectorf("line %d: section does not start with Keylen", lineNumber)
	}
	if _, exists := headers[name]; exists {
		return nil, invalidGCMVectorf("line %d: duplicate header %q", lineNumber, name)
	}
	bits, err := strconv.Atoi(value)
	if err != nil || bits < 0 {
		return nil, invalidGCMVectorf("line %d: invalid header value", lineNumber)
	}
	headers[name] = bits
	if (name == "IVlen" && bits != 96) || (name == "Taglen" && bits != 128) {
		return nil, invalidGCMVectorf("line %d: unsupported %s", lineNumber, name)
	}
	return headers, nil
}

func gcmVectorLengthsMatch(headers map[string]int, key, iv, pt, aad, ct, tag []byte, fail bool) bool {
	return len(key)*8 == headers["Keylen"] &&
		len(iv)*8 == headers["IVlen"] &&
		(fail || len(pt)*8 == headers["PTlen"]) &&
		len(aad)*8 == headers["AADlen"] &&
		len(ct)*8 == headers["PTlen"] &&
		len(tag)*8 == headers["Taglen"]
}

func invalidGCMVectorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errInvalidGCMVector, fmt.Sprintf(format, args...))
}

func newFixedNonceCrypterWithNonce(t *testing.T, key []byte, maximum int, nonce []byte) *AESGCMCrypter {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	wire := &fixedNonceWireAEAD{aead: aead, nonceSource: bytes.NewReader(nonce)}
	crypter, err := newAESGCMCrypter(wire, maximum)
	if err != nil {
		t.Fatal(err)
	}
	return crypter
}
