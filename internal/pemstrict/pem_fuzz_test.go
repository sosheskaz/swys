package pemstrict

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"maps"
	"testing"
)

const (
	maxFuzzPEMInputSize      = 1 << 12
	malformedFuzzPEMShapes   = 4
	maxFuzzPEMTrailingBlocks = 3
)

func FuzzDecode(f *testing.F) {
	valid := pem.EncodeToMemory(&pem.Block{
		Type:    "TEST DATA",
		Headers: map[string]string{"Comment": "fuzz seed"},
		Bytes:   []byte{0x00, 0x7f, 0x80, 0xff},
	})
	f.Add(valid, uint8(0), uint8(0))
	f.Add(append(bytes.Clone(valid), valid...), uint8(0), uint8(2))
	f.Add(append([]byte("-----BEGIN TEST DATA-----\n!\n-----END TEST DATA-----\n"), valid...), uint8(1), uint8(2))
	f.Add([]byte("-----BEGIN TEST DATA-----\n"), uint8(2), uint8(3))
	f.Add(append([]byte("-----BEGIN TEST DATA-----\n!\n-----END TEST DATA-----\n"), append(bytes.Clone(valid), valid...)...), uint8(0), uint8(0))
	f.Add([]byte{}, uint8(3), uint8(2))
	f.Add(valid, uint8(1), uint8(3))
	f.Add(valid, uint8(2), uint8(2))
	f.Add(valid, uint8(3), uint8(3))

	f.Fuzz(func(t *testing.T, data []byte, malformation, trailingBlocks uint8) {
		if len(data) > maxFuzzPEMInputSize {
			t.Skip()
		}

		original := bytes.Clone(data)
		block, rest := Decode(data)
		if !bytes.Equal(data, original) {
			t.Fatal("Decode modified its input")
		}
		if block == nil {
			if !bytes.Equal(rest, data) {
				t.Fatal("failed decode did not return the original input")
			}
		} else {
			checkFuzzPEMFirstBlock(t, data, block, rest)
		}

		checkValidFuzzPEM(t, data)
		checkMalformedFirstFuzzPEM(t, data, malformation, trailingBlocks)
	})
}

func checkFuzzPEMFirstBlock(t *testing.T, data []byte, block *pem.Block, rest []byte) {
	t.Helper()
	// encoding/pem skips malformed blocks, so it cannot witness strictness on its
	// own. The consumed prefix can only reach a later BEGIN line if the decoder
	// searched past a malformed first block.
	if consumed := data[:len(data)-len(rest)]; bytes.Contains(consumed, []byte("\n-----BEGIN ")) {
		t.Fatal("decoded block was taken from a later BEGIN line")
	}

	standard, standardRest := pem.Decode(data)
	if standard == nil {
		t.Fatal("strict decoder succeeded where encoding/pem rejected the input")
	}
	differs := block.Type != standard.Type || !bytes.Equal(block.Bytes, standard.Bytes) ||
		!maps.Equal(block.Headers, standard.Headers) || !bytes.Equal(rest, standardRest)
	if differs {
		t.Fatal("strict decode differs from encoding/pem for a valid first block")
	}
}

func checkValidFuzzPEM(t *testing.T, payload []byte) {
	t.Helper()
	encoded := pem.EncodeToMemory(&pem.Block{
		Type:    "FUZZ DATA",
		Headers: map[string]string{"Source": "generated"},
		Bytes:   payload,
	})
	input := append(bytes.Clone(encoded), payload...)

	block, rest := Decode(input)
	invalid := block == nil || block.Type != "FUZZ DATA" || !bytes.Equal(block.Bytes, payload) ||
		!maps.Equal(block.Headers, map[string]string{"Source": "generated"}) || !bytes.Equal(rest, payload)
	if invalid {
		t.Fatal("valid generated block did not preserve its fields and exact suffix")
	}
}

func checkMalformedFirstFuzzPEM(t *testing.T, payload []byte, malformation, trailingBlocks uint8) {
	t.Helper()
	shape := malformation % malformedFuzzPEMShapes
	trailing := trailingBlocks % (maxFuzzPEMTrailingBlocks + 1)
	first := malformedFirstFuzzPEM(payload, shape)
	input := append(bytes.Clone(first), trailingFuzzPEMBlocks(trailing)...)

	if standard, _ := pem.Decode(first); standard != nil {
		t.Fatalf("shape %d produced a decodable first block, so the strictness check proves nothing", shape)
	}

	block, rest := Decode(input)
	if block != nil {
		t.Fatalf("malformed first block (shape %d, %d trailing blocks) was skipped for %q", shape, trailing, block.Bytes)
	}
	if !bytes.Equal(rest, input) {
		t.Fatalf("rejected input (shape %d, %d trailing blocks) did not return the original bytes", shape, trailing)
	}
}

// malformedFirstFuzzPEM frames payload in a first block that no PEM decoder may
// accept. The payload is always base64 encoded, so only the surrounding
// structure decides validity and the premise holds for every generated input.
func malformedFirstFuzzPEM(payload []byte, shape uint8) []byte {
	body := base64.StdEncoding.EncodeToString(payload)
	switch shape {
	case 0: // a byte outside the base64 alphabet
		return []byte("-----BEGIN FUZZ DATA-----\n" + body + "!\n-----END FUZZ DATA-----\n")
	case 1: // no END line
		return []byte("-----BEGIN FUZZ DATA-----\n" + body + "\n")
	case 2: // END line naming another type
		return []byte("-----BEGIN FUZZ DATA-----\n" + body + "\n-----END OTHER DATA-----\n")
	default: // truncated after the BEGIN line
		return []byte("-----BEGIN FUZZ DATA-----\n")
	}
}

func trailingFuzzPEMBlocks(count uint8) []byte {
	var blocks []byte
	for i := range int(count) {
		blocks = append(blocks, pem.EncodeToMemory(&pem.Block{
			Type:  "FUZZ DATA",
			Bytes: fmt.Appendf(nil, "valid block %d", i+1),
		})...)
	}
	return blocks
}
