package help

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/interrupt"
)

func presentGuideThroughPager(
	command *cobra.Command,
	dependencies Dependencies,
	configuration string,
	rendered []byte,
) (result error) {
	arguments, err := parsePager(configuration)
	if err != nil {
		return err
	}
	commandContext := command.Context()
	if commandContext == nil {
		commandContext = context.Background()
	}
	pagerContext, releasePager := interrupt.PagerContext(commandContext)
	defer releasePager()
	process := dependencies.Command(pagerContext, arguments[0], arguments[1:]...)
	process.Stdout = command.OutOrStdout()
	process.Stderr = command.ErrOrStderr()
	input, err := process.StdinPipe()
	if err != nil {
		return warnAndWriteGuide(command, rendered, arguments[0], err)
	}
	// Let the foreground pager handle terminal interrupts while we wait to reap it.
	// Notify, unlike Ignore, does not make the child inherit ignored signals.
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, guidePagerInterruptSignals()...)
	defer signal.Stop(interrupts)
	stopTerminations := terminatePagerOnSignal(releasePager)
	defer func() {
		if received := stopTerminations(); received != nil && interrupt.Of(commandContext) == nil {
			if first := interrupt.FirstSignal(commandContext); first != nil {
				received = first
			}
			result = interrupt.NewError(received)
		}
	}()
	if err := process.Start(); err != nil {
		return warnAndWriteGuide(command, rendered, arguments[0], errors.Join(err, input.Close()))
	}

	writeErr := writeGuide(input, rendered)
	closeErr := input.Close()
	waitErr := process.Wait()
	if waitErr != nil {
		return fmt.Errorf(
			"pager %q failed: %w",
			arguments[0],
			errors.Join(withoutBrokenPipe(writeErr), withoutBrokenPipe(closeErr), waitErr),
		)
	}
	if err := errors.Join(withoutBrokenPipe(writeErr), withoutBrokenPipe(closeErr)); err != nil {
		return fmt.Errorf("write guide to pager %q: %w", arguments[0], err)
	}
	return nil
}

// terminatePagerOnSignal ends the pager on SIGTERM or SIGHUP. The root handler
// stops intercepting after its first signal, so without this a SIGTERM after a
// Ctrl-C the pager owned would kill swys and leave the pager running.
func terminatePagerOnSignal(terminate func()) func() os.Signal {
	signals := guidePagerTerminationSignals()
	if len(signals) == 0 {
		return func() os.Signal { return nil }
	}
	received := make(chan os.Signal, 1)
	signal.Notify(received, signals...)
	stop := terminateOnReceive(received, terminate)
	return func() os.Signal {
		signal.Stop(received)
		return stop()
	}
}

// terminateOnReceive is terminatePagerOnSignal with the signal source injected
// for tests. Once the returned stop func returns, terminate can no longer run.
func terminateOnReceive(received <-chan os.Signal, terminate func()) func() os.Signal {
	done := make(chan struct{})
	exited := make(chan struct{})
	var handled os.Signal
	go func() {
		defer close(exited)
		select {
		case handled = <-received:
			terminate()
		case <-done:
		}
	}()
	return func() os.Signal {
		close(done)
		<-exited
		return handled
	}
}

func warnAndWriteGuide(command *cobra.Command, rendered []byte, pager string, startErr error) error {
	_, warningErr := fmt.Fprintf(
		command.ErrOrStderr(),
		"warning: could not start pager %q: %v; writing guide directly\n",
		pager,
		startErr,
	)
	writeErr := writeGuide(command.OutOrStdout(), rendered)
	if err := errors.Join(warningErr, writeErr); err != nil {
		return fmt.Errorf("report pager failure and write guide directly: %w", err)
	}
	return nil
}

func withoutBrokenPipe(err error) error {
	if isBrokenPipe(err) {
		return nil
	}
	return err
}

func isBrokenPipe(err error) bool {
	return isPlatformBrokenPipe(err) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, os.ErrClosed)
}

type pagerQuoteMode uint8

const (
	pagerUnquoted pagerQuoteMode = iota
	pagerSingleQuoted
	pagerDoubleQuoted
)

type pagerParser struct {
	arguments             []string
	current               strings.Builder
	mode                  pagerQuoteMode
	escaped               bool
	escapedInDoubleQuotes bool
	started               bool
}

func parsePager(configuration string) ([]string, error) {
	parser := pagerParser{}
	for _, character := range configuration {
		if parser.escaped {
			parser.consumeEscaped(character)
			continue
		}
		switch parser.mode {
		case pagerUnquoted:
			parser.consumeUnquoted(character)
		case pagerSingleQuoted:
			parser.consumeSingleQuoted(character)
		case pagerDoubleQuoted:
			parser.consumeDoubleQuoted(character)
		}
	}
	if parser.escaped {
		return nil, fmt.Errorf("%w: trailing escape", ErrInvalidPager)
	}
	if parser.mode != pagerUnquoted {
		return nil, fmt.Errorf("%w: unterminated quote", ErrInvalidPager)
	}
	if parser.started {
		parser.flush()
	}
	if len(parser.arguments) == 0 || parser.arguments[0] == "" {
		return nil, fmt.Errorf("%w: expected an executable", ErrInvalidPager)
	}
	return parser.arguments, nil
}

func (parser *pagerParser) consumeEscaped(character rune) {
	if parser.escapedInDoubleQuotes && character != '"' && character != '\\' {
		parser.current.WriteByte('\\')
	}
	parser.current.WriteRune(character)
	parser.escaped = false
	parser.escapedInDoubleQuotes = false
	parser.started = true
}

func (parser *pagerParser) consumeUnquoted(character rune) {
	switch {
	case character == '\\':
		parser.escaped = true
		parser.started = true
	case character == '\'':
		parser.mode = pagerSingleQuoted
		parser.started = true
	case character == '"':
		parser.mode = pagerDoubleQuoted
		parser.started = true
	case unicode.IsSpace(character):
		if parser.started {
			parser.flush()
		}
	default:
		parser.current.WriteRune(character)
		parser.started = true
	}
}

func (parser *pagerParser) consumeSingleQuoted(character rune) {
	if character == '\'' {
		parser.mode = pagerUnquoted
		return
	}
	parser.current.WriteRune(character)
	parser.started = true
}

func (parser *pagerParser) consumeDoubleQuoted(character rune) {
	switch character {
	case '"':
		parser.mode = pagerUnquoted
	case '\\':
		parser.escaped = true
		parser.escapedInDoubleQuotes = true
	default:
		parser.current.WriteRune(character)
		parser.started = true
	}
}

func (parser *pagerParser) flush() {
	parser.arguments = append(parser.arguments, parser.current.String())
	parser.current.Reset()
	parser.started = false
}
