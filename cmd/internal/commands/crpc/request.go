package crpc

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"connectrpc.com/connect/v2"
	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/artifact"
	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/internal/connectrpc"
	"github.com/sosheskaz/swys/internal/contextio"
	"github.com/sosheskaz/swys/internal/httptransport"
)

type preparation struct {
	run   func(io.Writer) error
	close func() error
}

func prepare(cmd *cobra.Command, args []string, settings *options) (*preparation, error) {
	method := ""
	if len(args) == 2 {
		method = args[1]
	}
	endpoint, err := connectrpc.ParseEndpoint(args[0], method)
	if err != nil {
		return nil, err
	}
	if err := validate(cmd, settings, endpoint.URL.Scheme == "https"); err != nil {
		return nil, err
	}
	kind, err := streamType(settings.stream)
	if err != nil {
		return nil, err
	}
	headers, err := parseHeaders(settings.headers)
	if err != nil {
		return nil, err
	}
	resolver, err := httptransport.ParseResolves(settings.resolves)
	if err != nil {
		return nil, err
	}
	tlsOptions, err := prepareTLS(cmd, settings)
	if err != nil {
		return nil, err
	}
	client := connectrpc.NewClient(endpoint, connectrpc.Options{
		TLS: tlsOptions, Resolves: resolver, ConnectTimeout: settings.connectTimeout,
		Wait: settings.wait, MaxMessageSize: settings.maxMessageSize, RequireHTTP2: kind == connect.StreamTypeBidi,
	})
	if kind == connect.StreamTypeUnary {
		defer client.Close()
		output, err := prepareUnary(cmd, settings, client, headers)
		if err != nil {
			return nil, err
		}
		return &preparation{close: func() error { return nil }, run: func(writer io.Writer) error {
			if _, err := writer.Write(output); err != nil {
				return fmt.Errorf("write Connect response: %w", err)
			}
			return nil
		}}, nil
	}
	next, closeInput, err := prepareMessages(cmd, settings, kind)
	if err != nil {
		client.Close()
		return nil, err
	}
	return &preparation{
		close: func() error { client.Close(); return closeInput() },
		run: func(output io.Writer) error {
			ctx, cancel := commandio.NetworkSetupContext(cmd.Context(), settings.timeout)
			defer cancel()
			ctx, call := callContext(ctx, headers)
			callErr := client.Stream(ctx, kind, next, func(message jsontext.Value) error {
				if err := message.Compact(); err != nil {
					return fmt.Errorf("format response JSON: %w", err)
				}
				if _, err := output.Write(append(message, '\n')); err != nil {
					return fmt.Errorf("write response: %w", err)
				}
				return nil
			})
			if settings.verbose {
				return errors.Join(safeError(callErr), writeDiagnostics(ctx, cmd.ErrOrStderr(), call, callErr))
			}
			return safeError(callErr)
		},
	}, nil
}

func callContext(ctx context.Context, headers *connect.Header) (context.Context, *connect.CallInfo) {
	ctx, call := connect.NewClientContext(ctx)
	for name, values := range headers.All() {
		call.RequestHeader().SetValues(name, values)
	}
	return ctx, call
}

func prepareUnary(cmd *cobra.Command, settings *options, client *connectrpc.Client, headers *connect.Header) ([]byte, error) {
	request, err := readRequest(cmd, settings)
	if err != nil {
		return nil, err
	}
	value, err := connectrpc.ParseJSON(request)
	if err != nil {
		return nil, err
	}
	ctx, cancel := commandio.NetworkSetupContext(cmd.Context(), settings.timeout)
	defer cancel()
	ctx, call := callContext(ctx, headers)
	response, callErr := client.Unary(ctx, value)
	if settings.verbose {
		if err := writeDiagnostics(ctx, cmd.ErrOrStderr(), call, callErr); err != nil {
			return nil, errors.Join(safeError(callErr), err)
		}
	}
	if callErr != nil {
		return nil, safeError(callErr)
	}
	if settings.format == formatJSONL {
		if err := response.Compact(); err != nil {
			return nil, fmt.Errorf("format response JSON: %w", err)
		}
	}
	return append(response, '\n'), nil
}

func prepareMessages(cmd *cobra.Command, settings *options, kind connect.StreamType) (connectrpc.NextMessage, func() error, error) {
	if kind == connect.StreamTypeServer || cmd.Flags().Changed("data") {
		data, err := readRequest(cmd, settings)
		if err != nil {
			return nil, nil, err
		}
		value, err := connectrpc.ParseJSON(data)
		if err != nil {
			return nil, nil, err
		}
		return func(context.Context) (jsontext.Value, error) {
			if value == nil {
				return nil, io.EOF
			}
			message := value
			value = nil
			return message, nil
		}, func() error { return nil }, nil
	}
	decoder, err := commandio.InputDecoderFromCommand(cmd)
	if err != nil {
		return nil, nil, err
	}
	input := io.NopCloser(strings.NewReader(""))
	if cmd.Flags().Changed("input") && cmd.Flag("input").Value.String() != "-" {
		file, err := contextio.OpenFile(cmd.Context(), func() (*os.File, error) {
			return os.Open(cmd.Flag("input").Value.String())
		})
		if err != nil {
			return nil, nil, fmt.Errorf("open Connect input: %w", err)
		}
		input, err = contextio.NewOwnedFileReader(cmd.Context(), file)
		if err != nil {
			return nil, nil, fmt.Errorf("prepare Connect input: %w", err)
		}
	} else if usesStdin(cmd, settings) {
		input = io.NopCloser(cmd.InOrStdin())
	}
	var lines *connectrpc.JSONLines
	return func(ctx context.Context) (jsontext.Value, error) {
		if lines == nil {
			lines = connectrpc.NewJSONLines(decoder(contextio.NewReader(ctx, input)), settings.maxMessageSize)
		}
		return lines.Next()
	}, input.Close, nil
}

func readRequest(cmd *cobra.Command, settings *options) ([]byte, error) {
	decoder, err := commandio.InputDecoderFromCommand(cmd)
	if err != nil {
		return nil, err
	}
	var data []byte
	switch {
	case cmd.Flags().Changed("data"):
		data, err = artifact.Read(decoder(strings.NewReader(settings.data)), int64(settings.maxMessageSize))
	case cmd.Flags().Changed("input"):
		data, err = artifact.ReadEncodedSource(cmd.Context(), cmd.InOrStdin(), cmd.Flag("input").Value.String(), decoder, int64(settings.maxMessageSize))
	case usesStdin(cmd, settings):
		data, err = artifact.ReadEncodedSource(cmd.Context(), cmd.InOrStdin(), "-", decoder, int64(settings.maxMessageSize))
	}
	if err != nil {
		return nil, fmt.Errorf("read Connect request: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 && !cmd.Flags().Changed("data") && !cmd.Flags().Changed("input") {
		return []byte("{}"), nil
	}
	return data, nil
}
