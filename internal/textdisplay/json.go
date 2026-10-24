package textdisplay

import (
	"unicode"
	"unicode/utf8"
)

// EscapeJSONControls writes raw C1 controls and Unicode bidirectional
// formatting controls in valid JSON text as \u escapes. Valid JSON carries
// such runes only inside strings and never within an escape sequence, so the
// decoded value is unchanged. Other bytes, including invalid UTF-8, are copied
// verbatim. It returns value itself when nothing needs escaping.
func EscapeJSONControls(value []byte) []byte {
	var output []byte
	copied := 0
	for index := 0; index < len(value); {
		if value[index] < utf8.RuneSelf {
			index++
			continue
		}
		character, size := utf8.DecodeRune(value[index:])
		if (character >= 0x80 && character <= 0x9f) || unicode.Is(unicode.Bidi_Control, character) {
			const digits = "0123456789abcdef"
			output = append(output, value[copied:index]...)
			output = append(output, '\\', 'u',
				digits[character>>12&0xf], digits[character>>8&0xf], digits[character>>4&0xf], digits[character&0xf])
			copied = index + size
		}
		index += size
	}
	if output == nil {
		return value
	}
	return append(output, value[copied:]...)
}
