package cmd

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
		cleanup, err := configureIO(cmd)
		if err != nil {
			return err
		}
		state := &commandIO{cleanup: cleanup}
		cmd.SetContext(context.WithValue(cmd.Context(), commandIOKey{}, state))
		return nil
	},
	PersistentPostRunE: func(cmd *cobra.Command, _ []string) error {
		markCommandIOSuccessful(cmd)
		return closeCommandIO(cmd)
	},
}

type commandIOKey struct{}

type commandIO struct {
	cleanup    func(bool) error
	once       sync.Once
	successful bool
	err        error
}

func (state *commandIO) close() error {
	closed := false
	state.once.Do(func() {
		closed = true
		state.err = state.cleanup(state.successful)
	})
	if closed {
		return state.err
	}
	return nil
}

func markCommandIOSuccessful(cmd *cobra.Command) {
	if cmd == nil {
		return
	}
	state, ok := cmd.Context().Value(commandIOKey{}).(*commandIO)
	if ok {
		state.successful = true
	}
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

func configureIO(cmd *cobra.Command) (func(bool) error, error) {
	originalIn := cmd.InOrStdin()
	originalOut := cmd.OutOrStdout()
	var closers []io.Closer
	var stagedOutputPath string
	var stagedOutputMode os.FileMode
	var stagedOutputPreserveMode bool
	var outputPath string

	cleanup := func(commit bool) error {
		cmd.SetIn(originalIn)
		cmd.SetOut(originalOut)

		var closeErr error
		for i := len(closers) - 1; i >= 0; i-- {
			closeErr = errors.Join(closeErr, closers[i].Close())
		}
		return finishStagedOutput(stagedOutputPath, outputPath, stagedOutputMode, stagedOutputPreserveMode, commit, closeErr)
	}
	fail := func(err error) (func(bool) error, error) {
		return func(bool) error { return nil }, errors.Join(err, cleanup(false))
	}

	inputPath, err := cmd.Flags().GetString("input")
	if err != nil {
		return fail(fmt.Errorf("read input flag: %w", err))
	}
	outputPath, err = cmd.Flags().GetString("output")
	if err != nil {
		return fail(fmt.Errorf("read output flag: %w", err))
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
		output, temporaryPath, mode, preserveMode, openErr := openCommandOutput(outputPath)
		if openErr != nil {
			return fail(openErr)
		}
		stagedOutputPath = temporaryPath
		stagedOutputMode = mode
		stagedOutputPreserveMode = preserveMode
		var outputCloser io.Closer = output
		if temporaryPath != "" {
			// Only staged (regular-file) outputs benefit from fsync: it
			// forces the write durable to disk before the rename that makes
			// it visible, so a crash between them can't leave a renamed-but-
			// unflushed file. FIFOs and other non-regular targets stream
			// directly and skip it, since fsync on them is meaningless or
			// outright rejected by the OS.
			outputCloser = syncingFile{output}
		}
		closers = append(closers, outputCloser)
		cmd.SetOut(output)
	}

	output, closer := encoder(cmd.OutOrStdout())
	if closer != nil {
		closers = append(closers, closer)
	}
	cmd.SetOut(output)

	return cleanup, nil
}

// openCommandOutput decides whether an output path should be staged (written
// to a temporary file and atomically renamed into place) or opened directly.
// /dev/stdout, /dev/stderr, and /dev/fd/N (process substitution) are symlinks
// on Darwin and Linux, so the symlink bit alone can't decide this: staging a
// symlink to a FIFO tries to os.CreateTemp("/dev/fd", ...), which fails.
// Follow the symlink and stage only if the target is a regular file or does
// not exist yet; anything else (FIFO, device, socket) streams directly.
func openCommandOutput(outputPath string) (*os.File, string, os.FileMode, bool, error) {
	info, err := os.Lstat(outputPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return createStagedOutput(outputPath, 0, false)
	case err != nil:
		return nil, "", 0, false, fmt.Errorf("inspect output %q: %w", outputPath, err)
	case info.Mode()&os.ModeSymlink != 0:
		target, targetErr := os.Stat(outputPath)
		switch {
		case errors.Is(targetErr, os.ErrNotExist):
			return createStagedOutput(outputPath, 0, false)
		case targetErr != nil:
			return nil, "", 0, false, fmt.Errorf("inspect output %q: %w", outputPath, targetErr)
		case target.IsDir():
			return nil, "", 0, false, fmt.Errorf("output %q is a directory", outputPath)
		case target.Mode().IsRegular():
			return createStagedOutput(outputPath, target.Mode().Perm(), true)
		default:
			return openDirectOutput(outputPath)
		}
	case info.Mode().IsRegular():
		return createStagedOutput(outputPath, info.Mode().Perm(), true)
	case info.IsDir():
		return nil, "", 0, false, fmt.Errorf("output %q is a directory", outputPath)
	default:
		return openDirectOutput(outputPath)
	}
}

func openDirectOutput(outputPath string) (*os.File, string, os.FileMode, bool, error) {
	// The path is intentionally supplied by the CLI user.
	output, openErr := os.OpenFile(outputPath, os.O_WRONLY, 0) //nolint:gosec // opening an explicitly user-selected CLI path is intended
	if openErr != nil {
		return nil, "", 0, false, fmt.Errorf("open non-regular output %q: %w", outputPath, openErr)
	}
	return output, "", 0, false, nil
}

// createStagedOutput opens a temporary file beside outputPath. mode is the
// permission the destination should end up with once committed, and
// preserveMode says whether that permission should actually be applied: true
// when overwriting an existing destination (even one with mode 0), false for
// a newly created destination, which keeps the temp file's own private
// default. Staging only carries permission bits forward — setuid/setgid/
// sticky, ownership, and xattrs are not preserved, since rename-based
// staging always produces a fresh inode.
func createStagedOutput(outputPath string, mode os.FileMode, preserveMode bool) (*os.File, string, os.FileMode, bool, error) {
	output, err := os.CreateTemp(filepath.Dir(outputPath), "."+filepath.Base(outputPath)+".tmp-*")
	if err != nil {
		return nil, "", 0, false, fmt.Errorf("create temporary output for %q: %w", outputPath, err)
	}
	temporaryPath := output.Name()
	return output, temporaryPath, mode, preserveMode, nil
}

// syncingFile forces a staged output's contents to disk before it is closed,
// so the rename that follows can't outrun the data it's making visible: a
// crash between them would otherwise leave a renamed file with unflushed
// (possibly zero) content instead of failing the command outright.
type syncingFile struct {
	*os.File
}

// Close syncs before closing so durability doesn't depend on close ordering.
func (file syncingFile) Close() error {
	return errors.Join(file.Sync(), file.File.Close())
}

func finishStagedOutput(temporaryPath, destinationPath string, mode os.FileMode, preserveMode, commit bool, closeErr error) error {
	if temporaryPath == "" {
		return closeErr
	}
	if commit && closeErr == nil && preserveMode {
		if err := os.Chmod(temporaryPath, mode); err != nil {
			closeErr = fmt.Errorf("preserve output %q permissions: %w", destinationPath, err)
		}
	}
	if commit && closeErr == nil {
		err := os.Rename(temporaryPath, destinationPath)
		if err == nil {
			return nil
		}
		closeErr = fmt.Errorf("commit output %q: %w", destinationPath, err)
	}
	if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		closeErr = errors.Join(closeErr, fmt.Errorf("remove temporary output %q: %w", temporaryPath, err))
	}
	return closeErr
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
		return fmt.Errorf("input and output refer to the same file: %q", inputPath)
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
}
