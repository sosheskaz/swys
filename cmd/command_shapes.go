package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	encodingFlagName             = "encoding"
	inputEncodingFlagName        = "input-encoding"
	formatFlagName               = "format"
	defaultNetworkTimeout        = 10 * time.Second
	defaultNetworkWait           = 5 * time.Second
	commandShapeAnnotationPrefix = "npc.shape."
	binaryOutputShape            = "binary-output"
	sensitiveOutputShape         = "sensitive-output"
	structuredOutputShape        = "structured-output"
	networkShape                 = "network"
	compatibilityShape           = "compatibility"
)

var errInvalidHostPort = errors.New("invalid host:port")

func binaryOutputCommand(command *cobra.Command, acceptsInput bool) *cobra.Command {
	addCommandShape(command, binaryOutputShape)
	command.Flags().StringP(
		encodingFlagName,
		"e",
		"raw",
		"output encoding ("+strings.Join(byteEncodingNames(), ", ")+")",
	)
	registerFlagCompletion(command, encodingFlagName, byteEncodingNames)

	if acceptsInput {
		addInputEncodingFlag(command)
	}
	return command
}

func sensitiveBinaryOutputCommand(command *cobra.Command, acceptsInput bool) *cobra.Command {
	addCommandShape(command, sensitiveOutputShape)
	return binaryOutputCommand(command, acceptsInput)
}

func encodedInputCommand(command *cobra.Command) *cobra.Command {
	addInputEncodingFlag(command)
	return command
}

func addInputEncodingFlag(command *cobra.Command) {
	command.Flags().String(
		inputEncodingFlagName,
		"raw",
		"input encoding ("+strings.Join(byteEncodingNames(), ", ")+")",
	)
	registerFlagCompletion(command, inputEncodingFlagName, byteEncodingNames)
}

func structuredOutputCommand(command *cobra.Command, formats func() []string) *cobra.Command {
	addCommandShape(command, structuredOutputShape)
	command.Flags().StringP(
		formatFlagName,
		"f",
		"text",
		"structured output format ("+strings.Join(formats(), ", ")+")",
	)
	registerFlagCompletion(command, formatFlagName, formats)
	return command
}

func networkCommand(command *cobra.Command) *cobra.Command {
	addCommandShape(command, networkShape)
	command.Flags().Duration("timeout", defaultNetworkTimeout, "TCP setup and TLS handshake timeout (0 disables)")
	command.Args = networkAddressArgs(command.Args, false)

	if command.RunE == nil {
		panic(fmt.Sprintf("networkCommand: %q has no RunE; wrap a command that uses RunE, not Run", command.Use))
	}
	originalRunE := command.RunE
	command.RunE = func(cmd *cobra.Command, args []string) error {
		timeout, err := cmd.Flags().GetDuration("timeout")
		if err != nil {
			return fmt.Errorf("read timeout flag: %w", err)
		}
		originalContext := cmd.Context()
		ctx, cancel := networkSetupContext(originalContext, timeout)
		defer cancel()
		defer cmd.SetContext(originalContext)
		cmd.SetContext(ctx)
		return originalRunE(cmd, args)
	}
	return command
}

func networkSetupContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout == 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, timeout)
}

func streamNetworkCommand(command *cobra.Command) *cobra.Command {
	return streamNetworkCommandWithTimeout(
		command,
		defaultNetworkTimeout,
		"TCP setup and TLS handshake timeout (0 disables)",
		false,
	)
}

func listenStreamNetworkCommand(command *cobra.Command) *cobra.Command {
	return streamNetworkCommandWithTimeout(
		command,
		0,
		"bind resolution and accept timeout (0 disables)",
		true,
	)
}

func listenTLSStreamNetworkCommand(command *cobra.Command) *cobra.Command {
	return streamNetworkCommandWithTimeout(
		command,
		0,
		"bind resolution, accept, and TLS handshake timeout (0 disables)",
		true,
	)
}

func streamNetworkCommandWithTimeout(
	command *cobra.Command,
	defaultTimeout time.Duration,
	timeoutHelp string,
	allowEmptyHost bool,
) *cobra.Command {
	addCommandShape(command, networkShape)
	command.Flags().Duration("timeout", defaultTimeout, timeoutHelp)
	command.Flags().Duration(
		"wait",
		defaultNetworkWait,
		"maximum response drain time after input EOF; expiry returns an error with partial output preserved (0 waits indefinitely)",
	)
	command.Flags().Bool("close-write", false, "half-close the connection write side after input EOF")
	command.Flags().BoolP("verbose", "v", false, "write connection details to stderr")
	command.Args = networkAddressArgs(command.Args, allowEmptyHost)
	if command.RunE == nil {
		panic(fmt.Sprintf("streamNetworkCommand: %q has no RunE; wrap a command that uses RunE, not Run", command.Use))
	}
	return command
}

func networkAddressArgs(original cobra.PositionalArgs, allowEmptyHost bool) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(1)(cmd, args); err != nil {
			return err
		}
		if original != nil {
			if err := original(cmd, args); err != nil {
				return err
			}
		}
		address := args[0]
		if allowEmptyHost {
			var err error
			address, err = normalizeListenAddress(address)
			if err != nil {
				return err
			}
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("%w %q: %w", errInvalidHostPort, args[0], err)
		}
		if !allowEmptyHost && (host == "" || port == "") {
			return fmt.Errorf("%w %q: host and port are required", errInvalidHostPort, args[0])
		}
		if port == "" {
			return fmt.Errorf("%w %q: port is required", errInvalidHostPort, args[0])
		}
		return nil
	}
}

func normalizeListenAddress(address string) (string, error) {
	if strings.Contains(address, ":") {
		return address, nil
	}
	port, err := strconv.ParseUint(address, 10, 16)
	if err != nil {
		return "", fmt.Errorf("%w %q: bare port must be an integer from 0 to 65535", errInvalidHostPort, address)
	}
	return net.JoinHostPort("", strconv.FormatUint(port, 10)), nil
}

func compatibilityAliasCommand(command *cobra.Command) *cobra.Command {
	addCommandShape(command, compatibilityShape)
	return command
}

func addCommandShape(command *cobra.Command, shape string) {
	if command.Annotations == nil {
		command.Annotations = make(map[string]string)
	}
	command.Annotations[commandShapeAnnotationPrefix+shape] = "true"
}

func commandHasShape(command *cobra.Command, shape string) bool {
	return command.Annotations[commandShapeAnnotationPrefix+shape] == "true"
}

func compatibilityAliasInvoked(command *cobra.Command) bool {
	calledAs := command.CalledAs()
	return calledAs != "" && calledAs != command.Name() && slices.Contains(command.Aliases, calledAs)
}

func registerFlagCompletion(command *cobra.Command, name string, values func() []string) {
	if err := command.RegisterFlagCompletionFunc(
		name,
		func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			return values(), cobra.ShellCompDirectiveNoFileComp
		},
	); err != nil {
		panic(err)
	}
}

func commandInput(cmd *cobra.Command, args []string) (io.Reader, error) {
	if len(args) == 0 || args[0] == "-" {
		return cmd.InOrStdin(), nil
	}

	input := strings.NewReader(strings.Join(args, " "))
	decoder, err := inputDecoderFromCommand(cmd)
	if err != nil {
		return nil, err
	}
	return decoder(input), nil
}

// inputDecoderFromCommand is the single source of input-encoding decode
// policy, shared by commandInput's positional-argument path and configureIO's
// --input file path. A command that never registered --input-encoding (e.g.
// binaryOutputCommand with acceptsInput false) decodes as raw passthrough
// rather than erroring on the missing flag.
func inputDecoderFromCommand(cmd *cobra.Command) (inputDecoder, error) {
	if cmd.Flags().Lookup(inputEncodingFlagName) == nil {
		return func(input io.Reader) io.Reader { return input }, nil
	}
	name, err := cmd.Flags().GetString(inputEncodingFlagName)
	if err != nil {
		return nil, fmt.Errorf("read input-encoding flag: %w", err)
	}
	return getInputDecoder(name)
}
