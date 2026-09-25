package commandio

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/sosheskaz-systems/npc/internal/securefile"
)

// ErrOutputIsDirectory identifies a directory selected as an output file.
var (
	ErrOutputIsDirectory         = errors.New("output is a directory")
	ErrModeRequiresRegularOutput = errors.New("--mode requires a regular file output")
)

// OutputOptions controls output permissions and sensitive-file handling.
type OutputOptions struct {
	Mode      *os.FileMode
	Sensitive bool
}

// OpenOutput validates the selected path before opening it, then streams
// directly to the file. Stat follows symlinks like shell redirection.
func OpenOutput(outputPath string, options OutputOptions) (*os.File, error) {
	info, err := os.Stat(outputPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("inspect output %q: %w", outputPath, err)
	case info.IsDir():
		return nil, fmt.Errorf("%w: %q", ErrOutputIsDirectory, outputPath)
	case options.Mode != nil && !info.Mode().IsRegular():
		return nil, fmt.Errorf("%w: %q is not a regular file", ErrModeRequiresRegularOutput, outputPath)
	}
	output, err := openOutputFile(outputPath, options)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*os.File, error) { return nil, errors.Join(err, output.Close()) }
	info, err = output.Stat()
	if err != nil {
		return fail(fmt.Errorf("inspect opened output %q: %w", outputPath, err))
	}
	if options.Mode != nil {
		if !info.Mode().IsRegular() {
			return fail(fmt.Errorf("%w: %q is not a regular file", ErrModeRequiresRegularOutput, outputPath))
		}
		if err := output.Chmod(*options.Mode); err != nil {
			return fail(fmt.Errorf("set output %q permissions: %w", outputPath, err))
		}
	}
	if info.Mode().IsRegular() {
		if err := output.Truncate(0); err != nil {
			return fail(fmt.Errorf("truncate output %q: %w", outputPath, err))
		}
	}
	return output, nil
}

func openOutputFile(outputPath string, options OutputOptions) (*os.File, error) {
	if options.Sensitive && options.Mode == nil {
		output, err := securefile.OpenOrCreateOwnerOnly(outputPath)
		if errors.Is(err, securefile.ErrNotOwnerOnly) {
			remediation := "secure or remove the destination"
			if runtime.GOOS != "windows" {
				remediation += ", or pass --mode to override"
			}
			return nil, fmt.Errorf("refuse sensitive output %q: %w; %s", outputPath, err, remediation)
		}
		if err != nil {
			return nil, fmt.Errorf("open output %q: %w", outputPath, err)
		}
		return output, nil
	}
	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE, 0o600) //nolint:gosec // explicit user-selected CLI path
	if err != nil {
		return nil, fmt.Errorf("open output %q: %w", outputPath, err)
	}
	return output, nil
}
