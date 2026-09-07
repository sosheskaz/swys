// Package pemstrict decodes PEM without skipping malformed blocks.
package pemstrict

import (
	"bytes"
	"encoding/pem"
)

// Decode decodes the first block in data, which must start with a BEGIN line.
// On failure it returns nil and the original data, like pem.Decode.
func Decode(data []byte) (*pem.Block, []byte) {
	if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
		return nil, data
	}
	end := len(data)
	if next := bytes.Index(data, []byte("\n-----BEGIN ")); next >= 0 {
		// pem.Decode searches for a valid block. Hide subsequent BEGIN lines so
		// a malformed first block cannot silently disappear during that search.
		end = next + 1
	}
	block, rest := pem.Decode(data[:end])
	if block == nil {
		return nil, data
	}
	return block, data[end-len(rest):]
}
