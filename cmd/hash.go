package cmd

import (
	"crypto/md5"  //nolint:gosec // exposed explicitly for compatibility checks
	"crypto/sha1" //nolint:gosec // exposed explicitly for compatibility checks
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/spf13/cobra"
)

const (
	hashGroupShape  = "hash-group"
	hashOutputShape = "hash-output"
)

var (
	errUnknownHashAlgorithm = errors.New("unknown hash algorithm")
	hashAlgorithmNames      = []string{"sha256", "sha512", "sha1", "md5"}
	hashAlgorithms          = map[string]struct {
		constructor func() hash.Hash
		description string
	}{
		"sha256": {constructor: sha256.New, description: "Compute a SHA-256 digest"},
		"sha512": {constructor: sha512.New, description: "Compute a SHA-512 digest"},
		"sha1":   {constructor: sha1.New, description: "Compute a SHA-1 digest for compatibility"},
		"md5":    {constructor: md5.New, description: "Compute an MD5 digest for compatibility"},
	}
)

func newHashCmd() *cobra.Command {
	command := &cobra.Command{
		Use:   "hash",
		Short: "Compute a message digest",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			return fmt.Errorf("%w %q", errUnknownHashAlgorithm, args[0])
		},
	}
	addCommandShape(command, hashGroupShape)
	for _, name := range hashAlgorithmNames {
		command.AddCommand(newHashAlgorithmCmd(name, hashAlgorithms[name].description))
	}
	return command
}

func newHashAlgorithmCmd(name, description string) *cobra.Command {
	command := binaryOutputCommand(&cobra.Command{
		Use:   name,
		Short: description,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			digest, output, err := takePreparedOutput(cmd)
			if err != nil {
				return err
			}
			if _, err := output.Write(digest); err != nil {
				return fmt.Errorf("write %s digest: %w", name, err)
			}
			if err := finalizeOutputEncoding(output); err != nil {
				return fmt.Errorf("finalize digest encoding: %w", err)
			}
			encoding, err := cmd.Flags().GetString(encodingFlagName)
			if err != nil {
				return fmt.Errorf("read encoding flag: %w", err)
			}
			if encoding == "raw" {
				return nil
			}
			if _, err := writeUnencoded(output, []byte{'\n'}); err != nil {
				return fmt.Errorf("write digest newline: %w", err)
			}
			return nil
		},
	}, true)
	flag := command.Flags().Lookup(encodingFlagName)
	flag.DefValue = "hex"
	if err := flag.Value.Set("hex"); err != nil {
		panic(err)
	}
	addCommandShape(command, hashOutputShape)
	return command
}

func prepareHashOutput(cmd *cobra.Command, input io.Reader) ([]byte, error) {
	algorithm, ok := hashAlgorithms[cmd.Name()]
	if !ok {
		return nil, fmt.Errorf("%w %q", errUnknownHashAlgorithm, cmd.Name())
	}
	digest := algorithm.constructor()
	if _, err := io.Copy(digest, input); err != nil {
		return nil, fmt.Errorf("read hash input: %w", err)
	}
	return digest.Sum(nil), nil
}

func hashOutputEncoder(name string) (outputEncoder, error) {
	encoder, err := getOutputEncoder(name)
	if err != nil {
		return nil, err
	}
	return func(output io.Writer) (io.Writer, io.Closer) {
		encoded, closer := encoder(hashExactWriter{output: output})
		return encoded, hashEncodingCloser{closer: closer}
	}, nil
}

type hashExactWriter struct {
	output io.Writer
}

func (writer hashExactWriter) Write(data []byte) (int, error) {
	written, err := writer.output.Write(data)
	if err == nil && written != len(data) {
		err = io.ErrShortWrite
	}
	return written, err
}

type hashEncodingCloser struct {
	closer io.Closer
}

// Close finalizes a hash command's selected output encoder.
func (closer hashEncodingCloser) Close() error {
	if closer.closer == nil {
		return nil
	}
	if err := closer.closer.Close(); err != nil {
		return fmt.Errorf("close hash output encoder: %w", err)
	}
	return nil
}
