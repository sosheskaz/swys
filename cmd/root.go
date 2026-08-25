package cmd

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"sync"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/version"
)

var rootCmd = &cobra.Command{
	Use:           "npc",
	Version:       version.Get().String(),
	SilenceErrors: true,
	SilenceUsage:  true,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		if commandHasShape(cmd, compatibilityShape) && !compatibilityAliasInvoked(cmd) {
			return nil
		}
		if err := cmd.ValidateRequiredFlags(); err != nil {
			return fmt.Errorf("validate required flags: %w", err)
		}
		if err := cmd.ValidateFlagGroups(); err != nil {
			return fmt.Errorf("validate flag groups: %w", err)
		}
		if err := validateAESFlagsBeforeIO(cmd); err != nil {
			return fmt.Errorf("validate AES flags: %w", err)
		}
		if err := validateKeyFlagsBeforeIO(cmd); err != nil {
			return fmt.Errorf("validate key flags: %w", err)
		}
		cleanup, err := configureIO(cmd)
		if err != nil {
			return err
		}
		state := &commandIO{cleanup: cleanup}
		cmd.SetContext(context.WithValue(cmd.Context(), commandIOKey{}, state))
		return nil
	},
	PersistentPostRunE: func(cmd *cobra.Command, _ []string) error {
		return closeCommandIO(cmd)
	},
}

type commandIOKey struct{}

type commandIO struct {
	err     error
	cleanup func() error
	once    sync.Once
}

func (state *commandIO) close() error {
	closed := false
	state.once.Do(func() {
		closed = true
		state.err = state.cleanup()
	})
	if closed {
		return state.err
	}
	return nil
}

// Execute runs the root command.
func Execute() error {
	command, runErr := rootCmd.ExecuteC()
	if err := errors.Join(runErr, closeCommandIO(command)); err != nil {
		return fmt.Errorf("execute command: %w", err)
	}
	return nil
}

func closeCommandIO(cmd *cobra.Command) error {
	if cmd == nil {
		return nil
	}
	state, ok := cmd.Context().Value(commandIOKey{}).(*commandIO)
	if !ok {
		return nil
	}
	return state.close()
}

func generateIV(blockSize int) ([]byte, error) {
	iv := make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("generate IV: %w", err)
	}
	return iv, nil
}

func configureIO(cmd *cobra.Command) (func() error, error) {
	originalIn := cmd.InOrStdin()
	originalOut := cmd.OutOrStdout()
	var closers []io.Closer

	cleanup := func() error {
		cmd.SetIn(originalIn)
		cmd.SetOut(originalOut)

		var closeErr error
		for i := len(closers) - 1; i >= 0; i-- {
			closeErr = errors.Join(closeErr, closers[i].Close())
		}
		return closeErr
	}
	fail := func(err error) (func() error, error) {
		return func() error { return nil }, errors.Join(err, cleanup())
	}

	inputPath, err := cmd.Flags().GetString("input")
	if err != nil {
		return fail(fmt.Errorf("read input flag: %w", err))
	}
	outputPath, err := cmd.Flags().GetString("output")
	if err != nil {
		return fail(fmt.Errorf("read output flag: %w", err))
	}
	outputOptions, err := commandOutputOptionsFromCommand(cmd)
	if err != nil {
		return fail(err)
	}
	if outputOptions.mode != nil && outputPath == "" {
		return fail(fmt.Errorf("%w: --mode requires --output", errModeRequiresRegularOutput))
	}
	decoder, encoder, err := commandCodecs(cmd)
	if err != nil {
		return fail(err)
	}
	if err := rejectSameFile(inputPath, outputPath); err != nil {
		return fail(err)
	}

	if inputPath != "" {
		// The path is intentionally supplied by the CLI user.
		input, openErr := os.Open(inputPath) //nolint:gosec // opening an explicitly user-selected CLI path is intended
		if openErr != nil {
			return fail(fmt.Errorf("open %q for reading: %w", inputPath, openErr))
		}
		closers = append(closers, input)
		cmd.SetIn(decoder(input))
	} else {
		cmd.SetIn(decoder(cmd.InOrStdin()))
	}

	if outputPath != "" {
		// The path is intentionally supplied by the CLI user.
		output, openErr := openCommandOutput(outputPath, outputOptions)
		if openErr != nil {
			return fail(openErr)
		}
		closers = append(closers, output)
		cmd.SetOut(output)
	}

	output, closer := encoder(cmd.OutOrStdout())
	if closer != nil {
		closers = append(closers, closer)
	}
	cmd.SetOut(output)

	return cleanup, nil
}

type commandOutputOptions struct {
	mode *os.FileMode
}

// openCommandOutput validates what it can before opening the final path, then
// streams directly to it. Stat follows symlinks so output behaves like normal
// shell redirection and file-writing tools.
func openCommandOutput(outputPath string, options commandOutputOptions) (*os.File, error) {
	info, err := os.Stat(outputPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("inspect output %q: %w", outputPath, err)
	case info.IsDir():
		return nil, fmt.Errorf("%w: %q", errOutputIsDirectory, outputPath)
	case options.mode != nil && !info.Mode().IsRegular():
		return nil, fmt.Errorf("%w: %q is not a regular file", errModeRequiresRegularOutput, outputPath)
	}

	// The path is intentionally supplied by the CLI user.
	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE, 0o600) //nolint:gosec // opening an explicitly user-selected CLI path is intended
	if err != nil {
		return nil, fmt.Errorf("open output %q: %w", outputPath, err)
	}
	fail := func(err error) (*os.File, error) {
		return nil, errors.Join(err, output.Close())
	}

	info, err = output.Stat()
	if err != nil {
		return fail(fmt.Errorf("inspect opened output %q: %w", outputPath, err))
	}
	if options.mode != nil {
		if !info.Mode().IsRegular() {
			return fail(fmt.Errorf("%w: %q is not a regular file", errModeRequiresRegularOutput, outputPath))
		}
		if err := output.Chmod(*options.mode); err != nil {
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

var errInvalidOutputMode = errors.New("invalid output mode")

var errModeRequiresRegularOutput = errors.New("--mode requires a regular file output")

var errOutputModeUnsupported = errors.New("--mode is unsupported on this operating system")

// commandOutputOptionsFromCommand reads and validates output-specific flags.
// A nil mode means --mode was not set; an explicitly empty value is invalid.
func commandOutputOptionsFromCommand(cmd *cobra.Command) (commandOutputOptions, error) {
	return commandOutputOptionsForOS(cmd, runtime.GOOS)
}

func commandOutputOptionsForOS(cmd *cobra.Command, goos string) (commandOutputOptions, error) {
	if !cmd.Flags().Changed("mode") {
		return commandOutputOptions{}, nil
	}
	if goos == "windows" {
		return commandOutputOptions{}, fmt.Errorf("%w: windows exposes only a read-only file attribute", errOutputModeUnsupported)
	}
	text, err := cmd.Flags().GetString("mode")
	if err != nil {
		return commandOutputOptions{}, fmt.Errorf("read mode flag: %w", err)
	}
	mode, err := parseOutputMode(text)
	if err != nil {
		return commandOutputOptions{}, err
	}
	return commandOutputOptions{mode: &mode}, nil
}

func parseOutputMode(text string) (os.FileMode, error) {
	if text == "" {
		return 0, fmt.Errorf("%w %q: must not be empty", errInvalidOutputMode, text)
	}
	value, err := strconv.ParseUint(text, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("%w %q: %w", errInvalidOutputMode, text, err)
	}
	if value > 0o777 {
		return 0, fmt.Errorf("%w %q: must be at most 0777", errInvalidOutputMode, text)
	}
	return os.FileMode(value), nil
}

func commandCodecs(cmd *cobra.Command) (inputDecoder, outputEncoder, error) {
	decoder, err := inputDecoderFromCommand(cmd)
	if err != nil {
		return nil, nil, err
	}

	encoder := outputEncoder(func(output io.Writer) (io.Writer, io.Closer) { return output, nil })
	if cmd.Flags().Lookup(encodingFlagName) != nil {
		name, err := cmd.Flags().GetString(encodingFlagName)
		if err != nil {
			return nil, nil, fmt.Errorf("read encoding flag: %w", err)
		}
		encoder, err = getOutputEncoder(name)
		if err != nil {
			return nil, nil, err
		}
	}
	return decoder, encoder, nil
}

func rejectSameFile(inputPath, outputPath string) error {
	if inputPath == "" || outputPath == "" {
		return nil
	}

	inputInfo, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("stat input %q: %w", inputPath, err)
	}
	outputInfo, err := os.Stat(outputPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat output %q: %w", outputPath, err)
	}
	if os.SameFile(inputInfo, outputInfo) {
		return fmt.Errorf("%w: %q", errSameInputOutput, inputPath)
	}
	return nil
}

func init() {
	// Cobra otherwise runs only the nearest persistent hook, so a descendant
	// PersistentPreRunE would shadow the root's and silently disable --input,
	// --output, and encoding. Traversal makes the root I/O lifecycle
	// unshadowable: root's hooks run first inbound and last outbound.
	cobra.EnableTraverseRunHooks = true

	rootCmd.PersistentFlags().StringP("input", "i", "", "redirect stdin from this file")
	if err := rootCmd.MarkPersistentFlagFilename("input"); err != nil {
		panic(err)
	}
	rootCmd.PersistentFlags().StringP("output", "o", "", "redirect stdout to this file")
	if err := rootCmd.MarkPersistentFlagFilename("output"); err != nil {
		panic(err)
	}
	rootCmd.PersistentFlags().String(
		"mode",
		"",
		"POSIX octal permissions for the --output file (e.g. 0640); overrides the default 0600 on create and preserved permissions on overwrite",
	)
}
