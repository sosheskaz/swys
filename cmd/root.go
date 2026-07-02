package cmd

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:           "cryptool",
	SilenceErrors: true,
	SilenceUsage:  true,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
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
	cleanup func() error
	once    sync.Once
	err     error
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
	format, err := cmd.Flags().GetString("format")
	if err != nil {
		return fail(fmt.Errorf("read format flag: %w", err))
	}
	encoder, err := getOutputEncoder(format)
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
		cmd.SetIn(input)
	}

	if outputPath != "" {
		// The path is intentionally supplied by the CLI user.
		output, openErr := os.OpenFile( //nolint:gosec // opening an explicitly user-selected CLI path is intended
			outputPath,
			os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
			0o600,
		)
		if openErr != nil {
			return fail(fmt.Errorf("open %q for writing: %w", outputPath, openErr))
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
		return fmt.Errorf("input and output refer to the same file: %q", inputPath)
	}
	return nil
}

func init() {
	rootCmd.PersistentFlags().StringP("format", "f", "raw", "output encoding (base64, hex, raw)")
	rootCmd.PersistentFlags().StringP("input", "i", "", "redirect stdin from this file")
	if err := rootCmd.MarkPersistentFlagFilename("input"); err != nil {
		panic(err)
	}
	rootCmd.PersistentFlags().StringP("output", "o", "", "redirect stdout to this file")
	if err := rootCmd.MarkPersistentFlagFilename("output"); err != nil {
		panic(err)
	}
}
