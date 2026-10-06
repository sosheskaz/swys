// Package hash constructs streaming digest commands.
package hash

import (
	"crypto/md5"  //nolint:gosec // exposed explicitly for compatibility checks
	"crypto/sha1" //nolint:gosec // exposed explicitly for compatibility checks
	"crypto/sha256"
	"crypto/sha512"
	"embed"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/encoding"
	"github.com/sosheskaz/swys/cmd/internal/cli/help"
)

//go:embed guides
var hashGuideFiles embed.FS

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

// NewCommand constructs the hash command family for one root lifecycle.
func NewCommand(lifecycle *commandio.Lifecycle) *cobra.Command {
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
	lifecycle.Register(command, commandio.Behavior{SkipIO: true})
	for _, name := range hashAlgorithmNames {
		command.AddCommand(newHashAlgorithmCmd(lifecycle, name, hashAlgorithms[name].description))
	}
	if err := help.RegisterGuides(command, hashGuideFiles); err != nil {
		panic(err)
	}
	return command
}

func newHashAlgorithmCmd(lifecycle *commandio.Lifecycle, name, description string) *cobra.Command {
	command := commandio.BinaryOutputCommand(&cobra.Command{
		Use:               name,
		Short:             description,
		Args:              cobra.NoArgs,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			digest, output, err := commandio.TakePrepared(cmd)
			if err != nil {
				return err
			}
			if _, err := output.Write(digest); err != nil {
				return fmt.Errorf("write %s digest: %w", name, err)
			}
			if err := encoding.Finalize(output); err != nil {
				return fmt.Errorf("finalize digest encoding: %w", err)
			}
			encodingName, err := cmd.Flags().GetString(commandio.EncodingFlagName)
			if err != nil {
				return fmt.Errorf("read encoding flag: %w", err)
			}
			if encodingName == encoding.Raw {
				return nil
			}
			if _, err := encoding.WriteUnencoded(output, []byte{'\n'}); err != nil {
				return fmt.Errorf("write digest newline: %w", err)
			}
			return nil
		},
	}, true)
	flag := command.Flags().Lookup(commandio.EncodingFlagName)
	flag.DefValue = encoding.Hex
	if err := flag.Value.Set(encoding.Hex); err != nil {
		panic(err)
	}
	lifecycle.Register(command, commandio.Behavior{
		SupportsInput:  true,
		SupportsOutput: true,
		Prepare:        func(_ *cobra.Command, input io.Reader) ([]byte, error) { return prepareHashOutput(name, input) },
		OutputEncoder:  hashOutputEncoder,
	})
	return command
}

func prepareHashOutput(name string, input io.Reader) ([]byte, error) {
	algorithm, ok := hashAlgorithms[name]
	if !ok {
		return nil, fmt.Errorf("%w %q", errUnknownHashAlgorithm, name)
	}
	digest := algorithm.constructor()
	if _, err := io.Copy(digest, input); err != nil {
		return nil, fmt.Errorf("read hash input: %w", err)
	}
	return digest.Sum(nil), nil
}

func hashOutputEncoder(name string) (encoding.OutputEncoder, error) {
	encoder, err := encoding.GetOutputEncoder(name)
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
