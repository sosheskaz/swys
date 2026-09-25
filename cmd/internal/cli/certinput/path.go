package certinput

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/artifact"
)

// ErrPathCollision identifies an output that would overwrite a certificate input.
var ErrPathCollision = errors.New("certificate input and output paths collide")

// ValidatePaths checks source flags and --input against --output before file mutation.
// A source flag value of "-" selects stdin and is excluded from path comparison.
func ValidatePaths(cmd *cobra.Command, sourceFlags ...string) error {
	inputs, err := certificateInputPaths(cmd, sourceFlags)
	if err != nil {
		return err
	}
	outputs, err := certificateOutputPaths(cmd)
	if err != nil {
		return err
	}
	return rejectCertificatePathCollisions(inputs, outputs)
}

type namedCertificatePath struct {
	name string
	path string
}

func certificateInputPaths(cmd *cobra.Command, sourceFlags []string) ([]namedCertificatePath, error) {
	inputs := make([]namedCertificatePath, 0, len(sourceFlags)+1)
	for _, name := range sourceFlags {
		path, err := cmd.Flags().GetString(name)
		if err != nil {
			return nil, fmt.Errorf("read %s flag: %w", name, err)
		}
		if path != "" && path != "-" {
			inputs = append(inputs, namedCertificatePath{name: "--" + name, path: path})
		}
	}
	inputPath, err := cmd.Flags().GetString("input")
	if err != nil {
		return nil, fmt.Errorf("read input flag: %w", err)
	}
	if inputPath != "" {
		inputs = append(inputs, namedCertificatePath{name: "--input", path: inputPath})
	}
	return inputs, nil
}

func certificateOutputPaths(cmd *cobra.Command) ([]namedCertificatePath, error) {
	outputs := make([]namedCertificatePath, 0, 1)
	outputPath, err := cmd.Flags().GetString("output")
	if err != nil {
		return nil, fmt.Errorf("read output flag: %w", err)
	}
	if outputPath != "" {
		outputs = append(outputs, namedCertificatePath{name: "--output", path: outputPath})
	}
	return outputs, nil
}

func rejectCertificatePathCollisions(inputs, outputs []namedCertificatePath) error {
	for _, input := range inputs {
		for _, output := range outputs {
			if err := rejectCertificatePathPair(input, output); err != nil {
				return err
			}
		}
	}
	for i, left := range outputs {
		for _, right := range outputs[i+1:] {
			if err := rejectCertificatePathPair(left, right); err != nil {
				return err
			}
		}
	}
	return nil
}

func rejectCertificatePathPair(left, right namedCertificatePath) error {
	same, err := artifact.SamePath(left.path, right.path)
	if err != nil {
		return err
	}
	if !same {
		return nil
	}
	return fmt.Errorf("%w: %s and %s refer to %q", ErrPathCollision, left.name, right.name, left.path)
}
