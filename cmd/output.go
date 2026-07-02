package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

type outputEncoder func(io.Writer) (io.Writer, io.Closer)

var outputEncoders = map[string]outputEncoder{
	"raw": func(output io.Writer) (io.Writer, io.Closer) {
		return output, nil
	},
	"base64": base64Encoder,
	"b64":    base64Encoder,
	"hex": func(output io.Writer) (io.Writer, io.Closer) {
		return hex.NewEncoder(output), nil
	},
}

func getOutputEncoder(format string) (outputEncoder, error) {
	encoder, ok := outputEncoders[format]
	if !ok {
		return nil, fmt.Errorf("unknown output encoding %q (valid encodings: base64, hex, raw)", format)
	}
	return encoder, nil
}

func base64Encoder(output io.Writer) (io.Writer, io.Closer) {
	encoder := base64.NewEncoder(base64.StdEncoding, output)
	return encoder, encoder
}
