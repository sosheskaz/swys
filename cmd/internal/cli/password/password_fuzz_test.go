package password

import (
	"bytes"
	"testing"
)

func FuzzFirstLineAcrossWrites(f *testing.F) {
	f.Add([]byte("password\r\nignored"), uint16(9), uint16(10))
	f.Add([]byte(" leading and trailing \nnext"), uint16(0), uint16(7))
	f.Add([]byte("without newline\r"), uint16(3), uint16(12))
	f.Add(bytes.Repeat([]byte("x"), MaxBytes), uint16(17), uint16(1024))
	f.Add(append(bytes.Repeat([]byte("x"), MaxBytes), '\r', '\n'), uint16(4096), uint16(65535))
	f.Add(append(bytes.Repeat([]byte("x"), MaxBytes+2), '\n'), uint16(1000), uint16(65535))
	f.Fuzz(func(t *testing.T, data []byte, firstSplit, secondSplit uint16) {
		if len(data) > 2*MaxBytes+1024 {
			return
		}
		first := int(firstSplit) % (len(data) + 1)
		second := int(secondSplit) % (len(data) + 1)
		if second < first {
			first, second = second, first
		}
		var line firstLine
		for _, part := range [][]byte{data[:first], data[first:second], data[second:]} {
			n, err := line.Write(part)
			if err != nil || n != len(part) {
				t.Fatalf("Write returned %d, %v for %d bytes", n, err, len(part))
			}
		}
		at := bytes.IndexByte(data, '\n')
		expected := data
		if at >= 0 {
			expected = data[:at]
		}
		if line.tooLong != (len(expected) > MaxBytes+1) {
			t.Fatalf("tooLong=%t for first line of %d bytes", line.tooLong, len(expected))
		}
		if line.complete != (at >= 0 || line.tooLong) {
			t.Fatalf("complete=%t with LF at %d", line.complete, at)
		}
		if line.tooLong {
			return
		}
		if !bytes.Equal(expected, line.value) {
			t.Fatalf("stored first line differs across write boundaries")
		}
		if at >= 0 && len(expected) > 0 && expected[len(expected)-1] == '\r' {
			expected = expected[:len(expected)-1]
		}
		got := line.value
		if line.complete && len(got) > 0 && got[len(got)-1] == '\r' {
			got = got[:len(got)-1]
		}
		if !bytes.Equal(expected, got) {
			t.Fatal("CRLF handling differs from first-LF reference")
		}
		accepted := len(expected) > 0 && len(expected) <= MaxBytes
		if (Validate(got) == nil) != accepted {
			t.Fatalf("acceptance mismatch for %d-byte password", len(expected))
		}
	})
}
