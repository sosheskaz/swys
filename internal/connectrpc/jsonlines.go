package connectrpc

import (
	"bufio"
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
)

// ErrMessageSize identifies a JSON message rejected before parsing or sending.
var ErrMessageSize = errors.New("JSON message exceeds size limit")

// JSONLines reads bounded messages without Scanner's 64 KiB token limit.
type JSONLines struct {
	input *bufio.Reader
	limit int
}

// NewJSONLines reads one JSON value per nonblank line, accepting CRLF and final EOF.
func NewJSONLines(input io.Reader, limit int) *JSONLines {
	return &JSONLines{input: bufio.NewReader(input), limit: limit}
}

// Next returns io.EOF only between complete messages.
func (lines *JSONLines) Next() (jsontext.Value, error) {
	for {
		data, err := lines.readLine()
		if err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(data)) == 0 {
			continue
		}
		return ParseJSON(data)
	}
}

func (lines *JSONLines) readLine() ([]byte, error) {
	var data []byte
	for {
		part, err := lines.input.ReadSlice('\n')
		if lines.limit <= 0 || uint64(len(data))+uint64(len(part)) > uint64(lines.limit)+2 {
			return nil, fmt.Errorf("%w (%d bytes)", ErrMessageSize, lines.limit)
		}
		data = append(data, part...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("read JSON line: %w", err)
		}
		if len(data) == 0 && errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		data = bytes.TrimSuffix(data, []byte{'\n'})
		data = bytes.TrimSuffix(data, []byte{'\r'})
		if len(data) > lines.limit {
			return nil, fmt.Errorf("%w (%d bytes)", ErrMessageSize, lines.limit)
		}
		return data, nil
	}
}
