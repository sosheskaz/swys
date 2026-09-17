package cmd

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
)

func presentGuideThroughPager(
	command *cobra.Command,
	dependencies guideDependencies,
	configuration string,
	rendered []byte,
) error {
	arguments, err := parsePager(configuration)
	if err != nil {
		return err
	}
	commandContext := command.Context()
	if commandContext == nil {
		commandContext = context.Background()
	}
	process := dependencies.command(commandContext, arguments[0], arguments[1:]...)
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
		return nil, fmt.Errorf("%w: trailing escape", errInvalidPager)
	}
	if parser.mode != pagerUnquoted {
		return nil, fmt.Errorf("%w: unterminated quote", errInvalidPager)
	}
	if parser.started {
		parser.flush()
	}
	if len(parser.arguments) == 0 || parser.arguments[0] == "" {
		return nil, fmt.Errorf("%w: expected an executable", errInvalidPager)
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
