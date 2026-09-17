package cmd

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

type outputEncoder func(io.Writer) (io.Writer, io.Closer)

type inputDecoder func(io.Reader) io.Reader

type finalizingOutput struct {
	io.Writer
	closer     io.Closer
	underlying io.Writer
	err        error
	once       sync.Once
}

func (output *finalizingOutput) finalize() error {
	closed := false
	output.once.Do(func() {
		closed = true
		output.err = output.closer.Close()
	})
	if !closed {
		return nil
	}
	return output.err
}

// Close finalizes the encoder without closing its underlying output.
func (output *finalizingOutput) Close() error {
	return output.finalize()
}

func finalizeOutputEncoding(output io.Writer) error {
	finalizer, ok := output.(interface{ finalize() error })
	if !ok {
		return nil
	}
	return finalizer.finalize()
}

func writeUnencoded(output io.Writer, data []byte) (int, error) {
	finalizer, ok := output.(*finalizingOutput)
	if !ok || finalizer.underlying == nil {
		written, err := output.Write(data)
		if err == nil && written != len(data) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return written, fmt.Errorf("write unencoded output: %w", err)
		}
		return written, nil
	}
	written, err := finalizer.underlying.Write(data)
	if err == nil && written != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return written, fmt.Errorf("write unencoded output: %w", err)
	}
	return written, nil
}

type byteEncoding struct {
	encoder outputEncoder
	decoder inputDecoder
}

var byteEncodings = map[string]byteEncoding{
	"raw": {
		encoder: func(output io.Writer) (io.Writer, io.Closer) { return output, nil },
		decoder: func(input io.Reader) io.Reader { return input },
	},
	"hex": {
		encoder: func(output io.Writer) (io.Writer, io.Closer) { return hex.NewEncoder(output), nil },
		decoder: func(input io.Reader) io.Reader { return hex.NewDecoder(stripNewlines(input)) },
	},
	"base64": {
		encoder: base64Encoder(base64.StdEncoding),
		decoder: base64Decoder(base64.StdEncoding),
	},
	"b64": {
		encoder: base64Encoder(base64.StdEncoding),
		decoder: base64Decoder(base64.StdEncoding),
	},
	"base64url": {
		encoder: base64Encoder(base64.RawURLEncoding),
		decoder: base64URLDecoder,
	},
	"base32": {
		encoder: base32Encoder(base32.StdEncoding),
		decoder: base32Decoder(base32.StdEncoding),
	},
}

var errUnknownOutputEncoding = errors.New("unknown output encoding")

func getOutputEncoder(name string) (outputEncoder, error) {
	encoding, ok := byteEncodings[name]
	if !ok {
		return nil, fmt.Errorf("%w %q (valid: %s)", errUnknownOutputEncoding, name, strings.Join(byteEncodingNames(), ", "))
	}
	return encoding.encoder, nil
}

var errUnknownInputEncoding = errors.New("unknown input encoding")

func getInputDecoder(name string) (inputDecoder, error) {
	encoding, ok := byteEncodings[name]
	if !ok {
		return nil, fmt.Errorf("%w %q (valid: %s)", errUnknownInputEncoding, name, strings.Join(byteEncodingNames(), ", "))
	}
	return encoding.decoder, nil
}

// stripNewlines gives every text-based byte encoding the same leniency
// toward wrapped or trailing newlines. base64 and base32's stdlib decoders
// already skip '\r'/'\n' internally; encoding/hex does not, so without this
// a hex round trip breaks the moment anything (a shell, an editor) appends a
// trailing newline. Applying it uniformly keeps that policy from depending
// on which stdlib package happens to implement the encoding.
func stripNewlines(source io.Reader) io.Reader {
	return &newlineStrippingReader{source: source}
}

type newlineStrippingReader struct {
	source io.Reader
}

func (reader *newlineStrippingReader) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	// A read that strips only newlines can legitimately produce zero bytes
	// (e.g. a buffer full of "\r\n") with no error; loop rather than return
	// (0, nil), which would violate the io.Reader contract.
	for {
		read, err := reader.source.Read(buffer)
		written := 0
		for _, b := range buffer[:read] {
			if b == '\r' || b == '\n' {
				continue
			}
			buffer[written] = b
			written++
		}
		if written > 0 || err != nil {
			// Passed through unwrapped: some decoders (encoding/hex) compare err ==
			// io.EOF directly rather than through errors.Is, so wrapping it here would
			// silently break their truncated-input handling.
			return written, err //nolint:wrapcheck // preserve io.EOF identity for callers that compare it directly
		}
	}
}

func byteEncodingNames() []string {
	return sortedKeys(byteEncodings)
}

func base64Encoder(encoding *base64.Encoding) outputEncoder {
	return func(output io.Writer) (io.Writer, io.Closer) {
		encoder := base64.NewEncoder(encoding, output)
		return encoder, encoder
	}
}

func base64Decoder(encoding *base64.Encoding) inputDecoder {
	return func(input io.Reader) io.Reader {
		return base64.NewDecoder(encoding, &base64PaddingReader{source: stripNewlines(input)})
	}
}

var errInvalidBase64Padding = errors.New("invalid base64 padding")

// base64PaddingReader prevents the streaming decoder from treating terminal
// padding as a boundary between independently encoded values.
type base64PaddingReader struct {
	source      io.Reader
	pendingErr  error
	dataChars   int
	wantPadding bool
	terminal    bool
}

func (reader *base64PaddingReader) Read(buffer []byte) (int, error) {
	if reader.pendingErr != nil {
		return 0, reader.pendingErr
	}
	if len(buffer) == 0 {
		return 0, nil
	}

	read, readErr := reader.source.Read(buffer)
	written := 0
	var validationErr error
	for _, char := range buffer[:read] {
		if reader.terminal {
			validationErr = errInvalidBase64Padding
			break
		}

		buffer[written] = char
		written++
		switch {
		case reader.wantPadding:
			if char == '=' {
				reader.terminal = true
			}
			reader.wantPadding = false
		case char == '=' && reader.dataChars%4 == 2:
			reader.wantPadding = true
		case char == '=' && reader.dataChars%4 == 3:
			reader.terminal = true
		default:
			reader.dataChars++
		}
	}

	terminalErr := base64PaddingError(validationErr, readErr)
	if terminalErr != nil {
		reader.pendingErr = terminalErr
		if written > 0 {
			return written, nil
		}
	}
	return written, terminalErr
}

func base64PaddingError(validationErr, readErr error) error {
	if validationErr == nil {
		return readErr
	}
	// Only a plain terminal EOF is decoder control flow. An error that wraps EOF
	// is still a source failure and must remain discoverable through errors.Is.
	if readErr == nil || readErr == io.EOF { //nolint:errorlint // exact EOF identity is intentional
		return validationErr
	}
	return errors.Join(validationErr, readErr)
}

func base64URLDecoder(input io.Reader) io.Reader {
	return base64.NewDecoder(base64.RawURLEncoding, &optionalPaddingReader{source: stripNewlines(input)})
}

var errInvalidBase64URLPadding = errors.New("invalid base64url padding")

type optionalPaddingReader struct {
	source      io.Reader
	pendingErr  error
	dataChars   int
	padding     int
	seenPadding bool
}

func (reader *optionalPaddingReader) Read(buffer []byte) (int, error) {
	// Sticky per the io.Reader contract: once an error has been observed, every
	// later call must keep returning it instead of re-reading the source, which
	// for corrupt input could otherwise surface a misleading io.EOF.
	if reader.pendingErr != nil {
		return 0, reader.pendingErr
	}
	if len(buffer) == 0 {
		return 0, nil
	}

	// The source is pre-stripped of '\r'/'\n' by stripNewlines, so every byte
	// seen here is either padding or data.
	read, readErr := reader.source.Read(buffer)
	written := 0
	var validationErr error
	for _, char := range buffer[:read] {
		switch {
		case char == '=':
			reader.seenPadding = true
			reader.padding++
			if reader.padding > 2 {
				validationErr = errInvalidBase64URLPadding
			}
		case reader.seenPadding:
			validationErr = errInvalidBase64URLPadding
		default:
			reader.dataChars++
			buffer[written] = char
			written++
		}
	}

	var terminalErr error
	if readErr == io.EOF {
		if paddingErr := reader.validatePadding(); paddingErr != nil {
			terminalErr = errors.Join(validationErr, paddingErr)
		} else if validationErr != nil {
			terminalErr = validationErr
		} else {
			terminalErr = io.EOF
		}
	} else {
		terminalErr = errors.Join(validationErr, readErr)
	}
	if terminalErr != nil {
		reader.pendingErr = terminalErr
		if written > 0 {
			return written, nil
		}
	}
	return written, terminalErr
}

func (reader *optionalPaddingReader) validatePadding() error {
	switch {
	case reader.padding == 0:
		return nil
	case reader.padding == 1 && reader.dataChars%4 == 3:
		return nil
	case reader.padding == 2 && reader.dataChars%4 == 2:
		return nil
	default:
		return errInvalidBase64URLPadding
	}
}

func base32Encoder(encoding *base32.Encoding) outputEncoder {
	return func(output io.Writer) (io.Writer, io.Closer) {
		encoder := base32.NewEncoder(encoding, output)
		return encoder, encoder
	}
}

func base32Decoder(encoding *base32.Encoding) inputDecoder {
	return func(input io.Reader) io.Reader { return base32.NewDecoder(encoding, stripNewlines(input)) }
}
