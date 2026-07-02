package cmd

import (
	"encoding/base64"
	"io"

	"github.com/spf13/cobra"
)

type OutputFilter func(io.Reader, io.Writer) error

func NoOpOutputFilter(input io.Reader, output io.Writer) error {
	_, err := io.Copy(output, input)
	return err
}

func Base64OutputFilter(input io.Reader, output io.Writer) error {
	encoder := base64.NewEncoder(base64.StdEncoding, output)
	if _, err := io.Copy(encoder, input); err != nil {
		encoder.Close() //nolint:errcheck // copy error takes precedence
		return err
	}
	// Close flushes the final partial base64 group; its error matters
	return encoder.Close()
}

// b64Filter wraps the command's output writer in a base64 encoder and
// returns it as an io.Closer. base64.Encoder buffers partial 3-byte groups
// internally, so the caller must Close it after the command finishes writing
// or the final 1-2 bytes will be silently dropped.
func b64Filter(cmd *cobra.Command) io.Closer {
	enc := base64.NewEncoder(base64.StdEncoding, cmd.OutOrStdout())
	cmd.SetOut(enc)
	return enc
}
