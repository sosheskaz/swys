// Package encoding exposes a registry fixture to its external contract test.
package encoding

import "io"

// RegisterTestEncoding exposes the registry to its external consumer test only.
func RegisterTestEncoding(name string) func() {
	previous, existed := byteEncodings[name]
	byteEncodings[name] = byteEncoding{
		encoder: func(output io.Writer) (io.Writer, io.Closer) { return output, nil },
		decoder: func(input io.Reader) io.Reader { return input },
	}
	return func() {
		if existed {
			byteEncodings[name] = previous
		} else {
			delete(byteEncodings, name)
		}
	}
}
