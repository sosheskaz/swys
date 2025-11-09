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
	defer encoder.Close()
	_, err := io.Copy(encoder, input)
	return err
}

func b64Filter(cmd *cobra.Command) {
	cmd.SetOut(base64.NewEncoder(base64.StdEncoding, cmd.OutOrStdout()))
}
