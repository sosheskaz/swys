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

	"github.com/sosheskaz-systems/npc/internal/securefile"
	"github.com/sosheskaz-systems/npc/internal/version"
)

func newRootCmd() *cobra.Command {
	return newRootCmdWithDNSDependencies(defaultDNSDependencies())
}

func newRootCmdWithDNSDependencies(dnsDeps dnsDependencies) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "npc",
		Version:       version.Get().String(),
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			prepareHTTPCompletion(cmd, args)
			// HTTP prepares its body and DNS prepares its complete result before shared I/O setup.
			if commandHasShape(cmd, hashGroupShape) || commandHasShape(cmd, httpRequestShape) || commandHasShape(cmd, dnsQueryShape) {
				return nil
			}
			return configureCommandIO(cmd)
		},
		PersistentPostRunE: func(cmd *cobra.Command, _ []string) error {
			return closeCommandIO(cmd)
		},
	}
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
		"POSIX octal permissions for the --output file (e.g. 0640); explicitly overrides default, preserved, and sensitive-output permissions",
	)
	httpCmd := newHTTPCmd()
	rootCmd.AddCommand(newAesCmd(), newKeyCmd(), newCertCmd(), newHashCmd(), newNetCmd(), httpCmd, newDNSCmd(dnsDeps))
	registerHTTPBodyCompletionGroups(httpCmd)
	configureFishCompletionGeneration(rootCmd)
	return rootCmd
}

func configureCommandIO(cmd *cobra.Command) error {
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
	if err := validateCertFlagsBeforeIO(cmd); err != nil {
		return fmt.Errorf("validate certificate flags: %w", err)
	}
	if err := validateNetFlagsBeforeIO(cmd); err != nil {
		return fmt.Errorf("validate network flags: %w", err)
	}
	cleanup, preparedOutput, preparedWriter, err := configureIO(cmd)
	if err != nil {
		return err
	}
	originalContext := cmd.Context()
	state := &commandIO{preparedOutput: preparedOutput, preparedWriter: preparedWriter}
	state.cleanup = func() error {
		defer func() {
			state.preparedOutput = nil
			state.preparedWriter = nil
			cmd.SetContext(originalContext)
		}()
		return cleanup()
	}
	cmd.SetContext(context.WithValue(originalContext, commandIOKey{}, state))
	return nil
}

type commandIOKey struct{}

type commandIO struct {
	err            error
	cleanup        func() error
	preparedWriter io.Writer
	preparedOutput []byte
	once           sync.Once
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
	return executeCommand(newRootCmd())
}

func executeCommand(root *cobra.Command) error {
	command, runErr := root.ExecuteC()
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

func configureIO(cmd *cobra.Command) (func() error, []byte, io.Writer, error) {
	originalIn := cmd.InOrStdin()
	originalOut := cmd.OutOrStdout()
	preparesOutput := commandPreparesOutput(cmd)
	var closers []io.Closer

	cleanup := func() error {
		restoreConfiguredStreams(cmd, originalIn, originalOut, preparesOutput)

		var closeErr error
		for i := len(closers) - 1; i >= 0; i-- {
			closeErr = errors.Join(closeErr, closers[i].Close())
		}
		return closeErr
	}
	fail := func(err error) (func() error, []byte, io.Writer, error) {
		return func() error { return nil }, nil, nil, errors.Join(err, cleanup())
	}

	inputPath, err := commandInputPath(cmd)
	if err != nil {
		return fail(err)
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

	input := originalIn
	if inputPath != "" {
		// The path is intentionally supplied by the CLI user.
		openedInput, openErr := os.Open(inputPath) //nolint:gosec // opening an explicitly user-selected CLI path is intended
		if openErr != nil {
			return fail(fmt.Errorf("open %q for reading: %w", inputPath, openErr))
		}
		closers = append(closers, openedInput)
		input = openedInput
	}
	input = decoder(input)
	setConfiguredInput(cmd, input, preparesOutput)

	preparedOutput, err := prepareCommandOutput(cmd, input)
	if err != nil {
		return fail(err)
	}

	output := originalOut
	if outputPath != "" {
		// The path is intentionally supplied by the CLI user.
		openedOutput, openErr := openCommandOutput(outputPath, outputOptions)
		if openErr != nil {
			return fail(openErr)
		}
		closers = append(closers, openedOutput)
		output = openedOutput
	}

	underlyingOutput := output
	output, closer := encoder(output)
	if closer != nil {
		finalizer := &finalizingOutput{Writer: output, closer: closer, underlying: underlyingOutput}
		closers = append(closers, finalizer)
		output = finalizer
	}
	setConfiguredOutput(cmd, output, preparesOutput)

	return cleanup, preparedOutput, output, nil
}

func commandInputPath(cmd *cobra.Command) (string, error) {
	if commandHasShape(cmd, httpRequestShape) {
		// HTTP already opened its selected body before output setup.
		return "", nil
	}
	path, err := cmd.Flags().GetString("input")
	if err != nil {
		return "", fmt.Errorf("read input flag: %w", err)
	}
	return path, nil
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
) {
	if preparesOutput {
		return
	}
	restoreCommandStreams(cmd, input, output)
}

func takePreparedOutput(cmd *cobra.Command) ([]byte, io.Writer, error) {
	state, ok := cmd.Context().Value(commandIOKey{}).(*commandIO)
	if !ok || state.preparedOutput == nil || state.preparedWriter == nil {
		return nil, nil, errPreparedOutputUnavailable
	}
	prepared := state.preparedOutput
	writer := state.preparedWriter
	state.preparedOutput = nil
	state.preparedWriter = nil
	return prepared, writer, nil
}

func restoreCommandStreams(cmd *cobra.Command, input io.Reader, output io.Writer) {
	if commandHasShape(cmd, httpRequestShape) {
		// HTTP commands inherit streams from the root. Clear temporary
		// bindings so a reused command tree sees its newly supplied streams.
		cmd.SetIn(nil)
		cmd.SetOut(nil)
		return
	}
	cmd.SetIn(input)
	cmd.SetOut(output)
}

type commandOutputOptions struct {
	mode      *os.FileMode
	sensitive bool
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

	output, err := openCommandOutputFile(outputPath, options)
	if err != nil {
		return nil, err
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

func openCommandOutputFile(outputPath string, options commandOutputOptions) (*os.File, error) {
	if options.sensitive && options.mode == nil {
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

	// The path is intentionally supplied by the CLI user.
	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE, 0o600) //nolint:gosec // opening an explicitly user-selected CLI path is intended
	if err != nil {
		return nil, fmt.Errorf("open output %q: %w", outputPath, err)
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
	options := commandOutputOptions{sensitive: commandHasShape(cmd, sensitiveOutputShape)}
	if commandHasShape(cmd, "key-convert") {
		target, err := keyConversionTargetFromCommand(cmd)
		if err != nil {
			return commandOutputOptions{}, err
		}
		options.sensitive = !isPublicKeyFormat(target)
	}
	if !cmd.Flags().Changed("mode") {
		return options, nil
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
	options.mode = &mode
	return options, nil
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
		if commandHasShape(cmd, hashOutputShape) {
			encoder, err = hashOutputEncoder(name)
		} else {
			encoder, err = getOutputEncoder(name)
		}
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
}
