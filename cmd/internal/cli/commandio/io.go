package commandio

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/encoding"
	"github.com/sosheskaz-systems/npc/internal/contextio"
)

// Configure validates flags and installs command streams and cleanup.
func Configure(cmd *cobra.Command, behavior *Behavior) error {
	return configureCommandIOWithBehavior(cmd, behavior, nil)
}

func configureCommandIOWithBehavior(cmd *cobra.Command, behavior *Behavior, setup *ioSetup) error {
	if err := cmd.ValidateRequiredFlags(); err != nil {
		return fmt.Errorf("validate required flags: %w", err)
	}
	if err := cmd.ValidateFlagGroups(); err != nil {
		return fmt.Errorf("validate flag groups: %w", err)
	}
	if behavior != nil && behavior.Validate != nil {
		if err := behavior.Validate(cmd); err != nil {
			return err
		}
	}
	originalContext := cmd.Context()
	cleanup, preparedOutput, preparedWriter, err := configureIO(cmd, behavior, setup)
	if err != nil {
		return err
	}
	Install(cmd.Context(), originalContext, cmd, preparedOutput, preparedWriter, cleanup)
	return nil
}

func configureIO(cmd *cobra.Command, behavior *Behavior, preflight *ioSetup) (func() error, []byte, io.Writer, error) {
	originalContext := cmd.Context()
	originalIn := cmd.InOrStdin()
	originalOut := cmd.OutOrStdout()
	preparesOutput := behavior != nil && behavior.Prepare != nil
	var closers []io.Closer

	cleanup := func() error {
		restoreConfiguredStreams(cmd, originalIn, originalOut, preparesOutput, behavior)

		var closeErr error
		for i := len(closers) - 1; i >= 0; i-- {
			closeErr = errors.Join(closeErr, closers[i].Close())
		}
		return closeErr
	}
	fail := func(err error) (func() error, []byte, io.Writer, error) {
		cmd.SetContext(originalContext)
		return func() error { return nil }, nil, nil, errors.Join(err, cleanup())
	}

	var setup ioSetup
	var err error
	if preflight != nil {
		setup = *preflight
	} else {
		setup, err = readIOSetup(cmd, behavior)
		if err != nil {
			return fail(err)
		}
	}

	input := originalIn
	if setup.inputPath != "" {
		openedInput, openErr := OpenInput(cmd.Context(), setup.inputPath)
		if openErr != nil {
			return fail(openErr)
		}
		closers = append(closers, openedInput)
		input = openedInput
	}
	input = setup.decoder(contextio.NewReader(cmd.Context(), input))
	setConfiguredInput(cmd, input, preparesOutput)

	if behavior != nil && behavior.PrepareInput != nil {
		if err := behavior.PrepareInput(cmd); err != nil {
			return fail(err)
		}
	}

	var preparedOutput []byte
	if behavior != nil && behavior.Prepare != nil {
		preparedOutput, err = behavior.Prepare(cmd, input)
	}
	if err != nil {
		return fail(err)
	}

	output, outputClosers, err := openEncodedOutput(cmd, setup, originalOut)
	if err != nil {
		return fail(err)
	}
	closers = append(closers, outputClosers...)
	setConfiguredOutput(cmd, output, preparesOutput)

	return cleanup, preparedOutput, output, nil
}

type ioSetup struct {
	inputPath, outputPath string
	decoder               encoding.InputDecoder
	encoder               encoding.OutputEncoder
	outputOptions         OutputOptions
}

func readIOSetup(cmd *cobra.Command, behavior *Behavior) (ioSetup, error) {
	var setup ioSetup
	var err error
	if behavior == nil || !behavior.InputPrepared {
		setup.inputPath, err = commandInputPath(cmd)
		if err != nil {
			return ioSetup{}, err
		}
	}
	setup.outputPath, err = cmd.Flags().GetString("output")
	if err != nil {
		return ioSetup{}, fmt.Errorf("read output flag: %w", err)
	}
	setup.outputPath = NormalizeMainStreamPath(setup.outputPath)
	setup.outputOptions, err = commandOutputOptionsWithBehavior(cmd, behavior, runtime.GOOS)
	if err != nil {
		return ioSetup{}, err
	}
	if err := validateCommandOutputMode(setup.outputPath, setup.outputOptions); err != nil {
		return ioSetup{}, err
	}
	setup.decoder, setup.encoder, err = commandCodecs(cmd, behavior)
	if err != nil {
		return ioSetup{}, err
	}
	if err := RejectSameFile(setup.inputPath, setup.outputPath); err != nil {
		return ioSetup{}, err
	}
	return setup, nil
}

func openEncodedOutput(cmd *cobra.Command, setup ioSetup, original io.Writer) (io.Writer, []io.Closer, error) {
	output := original
	var closers []io.Closer
	if setup.outputPath != "" {
		// The path is intentionally supplied by the CLI user.
		opened, err := contextio.OpenFile(cmd.Context(), func() (*os.File, error) {
			return OpenOutput(setup.outputPath, setup.outputOptions)
		})
		if err != nil {
			return nil, nil, err
		}
		closers = append(closers, opened)
		output = opened
	}
	underlying := output
	output, closer := setup.encoder(output)
	if closer != nil {
		finalizer := encoding.NewFinalizingOutput(output, closer, underlying)
		closers = append(closers, finalizer)
		output = finalizer
	}
	return output, closers, nil
}

func validateCommandOutputMode(outputPath string, options commandOutputOptions) error {
	if options.Mode != nil && outputPath == "" {
		return ErrModeRequiresRegularOutput
	}
	return nil
}

func commandInputPath(cmd *cobra.Command) (string, error) {
	path, err := cmd.Flags().GetString("input")
	if err != nil {
		return "", fmt.Errorf("read input flag: %w", err)
	}
	return NormalizeMainStreamPath(path), nil
}

func setConfiguredInput(cmd *cobra.Command, input io.Reader, preparesOutput bool) {
	if !preparesOutput {
		cmd.SetIn(input)
	}
}

func setConfiguredOutput(cmd *cobra.Command, output io.Writer, preparesOutput bool) {
	if !preparesOutput {
		cmd.SetOut(output)
	}
}

func restoreConfiguredStreams(
	cmd *cobra.Command,
	input io.Reader,
	output io.Writer,
	preparesOutput bool,
	behavior *Behavior,
) {
	if preparesOutput {
		return
	}
	if behavior != nil && behavior.ClearInheritedStreams {
		cmd.SetIn(nil)
		cmd.SetOut(nil)
		return
	}
	restoreCommandStreams(cmd, input, output)
}

func restoreCommandStreams(cmd *cobra.Command, input io.Reader, output io.Writer) {
	cmd.SetIn(input)
	cmd.SetOut(output)
}

type commandOutputOptions = OutputOptions

// ErrInvalidOutputMode identifies a malformed or out-of-range octal mode.
var ErrInvalidOutputMode = errors.New("invalid output mode")

// ErrOutputModeUnsupported identifies an explicit mode on unsupported systems.
var ErrOutputModeUnsupported = errors.New("--mode is unsupported on this operating system")

func commandOutputOptionsWithBehavior(cmd *cobra.Command, behavior *Behavior, goos string) (commandOutputOptions, error) {
	options := commandOutputOptions{Sensitive: HasShape(cmd, "sensitive-output")}
	if behavior != nil && behavior.Sensitive != nil {
		sensitive, err := behavior.Sensitive(cmd)
		if err != nil {
			return commandOutputOptions{}, err
		}
		options.Sensitive = sensitive
	}
	if !cmd.Flags().Changed("mode") {
		return options, nil
	}
	if goos == "windows" {
		return commandOutputOptions{}, fmt.Errorf("%w: windows exposes only a read-only file attribute", ErrOutputModeUnsupported)
	}
	text, err := cmd.Flags().GetString("mode")
	if err != nil {
		return commandOutputOptions{}, fmt.Errorf("read mode flag: %w", err)
	}
	mode, err := parseOutputMode(text)
	if err != nil {
		return commandOutputOptions{}, err
	}
	options.Mode = &mode
	return options, nil
}

func parseOutputMode(text string) (os.FileMode, error) {
	if text == "" {
		return 0, fmt.Errorf("%w %q: must not be empty", ErrInvalidOutputMode, text)
	}
	value, err := strconv.ParseUint(text, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("%w %q: %w", ErrInvalidOutputMode, text, err)
	}
	if value > 0o777 {
		return 0, fmt.Errorf("%w %q: must be at most 0777", ErrInvalidOutputMode, text)
	}
	return os.FileMode(value), nil
}

func commandCodecs(cmd *cobra.Command, behavior *Behavior) (encoding.InputDecoder, encoding.OutputEncoder, error) {
	decoder, err := InputDecoderFromCommand(cmd)
	if err != nil {
		return nil, nil, err
	}

	encoder := encoding.OutputEncoder(func(output io.Writer) (io.Writer, io.Closer) { return output, nil })
	if cmd.Flags().Lookup(EncodingFlagName) != nil {
		name, err := cmd.Flags().GetString(EncodingFlagName)
		if err != nil {
			return nil, nil, fmt.Errorf("read encoding flag: %w", err)
		}
		if behavior != nil && behavior.OutputEncoder != nil {
			encoder, err = behavior.OutputEncoder(name)
		} else {
			encoder, err = encoding.GetOutputEncoder(name)
		}
		if err != nil {
			return nil, nil, err
		}
	}
	return decoder, encoder, nil
}

func init() {
	// Cobra otherwise runs only the nearest persistent hook, so a descendant
	// PersistentPreRunE would shadow the root's and silently disable --input,
	// --output, and encoding. Traversal makes the root I/O lifecycle
	// unshadowable: root's hooks run first inbound and last outbound.
	cobra.EnableTraverseRunHooks = true
}
