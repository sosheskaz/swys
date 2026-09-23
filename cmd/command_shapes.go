package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
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
	defaultStreamConnectTimeout  = 5 * time.Second
	commandShapeAnnotationPrefix = "npc.shape."
	binaryOutputShape            = "binary-output"
	sensitiveOutputShape         = "sensitive-output"
	structuredOutputShape        = "structured-output"
	networkShape                 = "network"
	streamNetworkShape           = "stream-network"
)

var durationCompletionValues = []struct {
	value       string
	description string
}{
	{value: "0"},
	{value: "1s", description: "One second"},
	{value: "5s", description: "Five seconds"},
	{value: "10s", description: "Ten seconds"},
	{value: "30s", description: "Thirty seconds"},
}

var errInvalidHostPort = errors.New("invalid host:port")

func binaryOutputCommand(command *cobra.Command, acceptsInput bool) *cobra.Command {
	addCommandShape(command, binaryOutputShape)
	command.Flags().StringP(
		encodingFlagName,
		"e",
		"raw",
		"output encoding ("+strings.Join(byteEncodingNames(), ", ")+")",
	)
	registerDescribedFlagCompletion(command, encodingFlagName, byteEncodingNames, byteEncodingDescriptions)

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
	registerDescribedFlagCompletion(command, inputEncodingFlagName, byteEncodingNames, byteEncodingDescriptions)
}

func structuredOutputCommand(command *cobra.Command, formats func() []string) *cobra.Command {
	addCommandShape(command, structuredOutputShape)
	command.Flags().StringP(
		formatFlagName,
		"f",
		"text",
		"structured output format ("+strings.Join(formats(), ", ")+")",
	)
	registerDescribedFlagCompletion(command, formatFlagName, formats, structuredFormatDescriptions)
	return command
}

func networkCommand(command *cobra.Command) *cobra.Command {
	addCommandShape(command, networkShape)
	command.Flags().Duration("timeout", defaultNetworkTimeout, "TCP setup and TLS handshake timeout (0 disables)")
	registerDurationCompletion(command, "timeout", "Disable TCP setup and TLS handshake timeout")
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
		defaultStreamConnectTimeout,
		"TCP setup and TLS handshake timeout (0 disables)",
		false,
	)
}

func connectDatagramNetworkCommand(command *cobra.Command) *cobra.Command {
	addCommandShape(command, networkShape)
	command.Flags().Duration("timeout", defaultNetworkTimeout, "UDP address resolution and socket setup timeout (0 disables)")
	command.Flags().Duration(
		"wait",
		defaultNetworkWait,
		"maximum wait for one response datagram after sending (0 waits indefinitely)",
	)
	registerDurationCompletion(command, "timeout", "Disable UDP address resolution and socket setup timeout")
	registerDurationCompletion(command, "wait", "Wait indefinitely for a response datagram")
	command.Flags().BoolP("verbose", "v", false, "write connection details to stderr")
	command.Args = networkAddressArgs(command.Args, false)
	command.ValidArgsFunction = cobra.NoFileCompletions
	if command.RunE == nil {
		panic(fmt.Sprintf("connectDatagramNetworkCommand: %q has no RunE; wrap a command that uses RunE, not Run", command.Use))
	}
	return command
}

func listenStreamNetworkCommand(command *cobra.Command) *cobra.Command {
	command = streamNetworkCommandWithTimeout(
		command,
		0,
		"bind resolution and accept timeout (0 disables)",
		true,
	)
	command.Flags().BoolP("recv-only", "r", false, "receive peer data without reading or sending input")
	return command
}

func listenDatagramNetworkCommand(command *cobra.Command) *cobra.Command {
	addCommandShape(command, networkShape)
	command.Flags().Duration("timeout", 0, "bind resolution and first datagram timeout (0 disables)")
	registerDurationCompletion(command, "timeout", "Disable bind resolution and first datagram timeout")
	command.Flags().BoolP("verbose", "v", false, "write connection details to stderr")
	command.Args = networkAddressArgs(command.Args, true)
	command.ValidArgsFunction = cobra.NoFileCompletions
	if command.RunE == nil {
		panic(fmt.Sprintf("listenDatagramNetworkCommand: %q has no RunE; wrap a command that uses RunE, not Run", command.Use))
	}
	return command
}

func listenTLSStreamNetworkCommand(command *cobra.Command) *cobra.Command {
	command = streamNetworkCommandWithTimeout(
		command,
		0,
		"bind resolution, accept, and TLS handshake timeout (0 disables)",
		true,
	)
	command.Flags().BoolP("recv-only", "r", false, "receive peer data without reading or sending input")
	return command
}

func streamNetworkCommandWithTimeout(
	command *cobra.Command,
	defaultTimeout time.Duration,
	timeoutHelp string,
	allowEmptyHost bool,
) *cobra.Command {
	addCommandShape(command, streamNetworkShape)
	addCommandShape(command, networkShape)
	command.Flags().Duration("timeout", defaultTimeout, timeoutHelp)
	command.Flags().Duration(
		"wait",
		0,
		"maximum response drain time after input EOF; expiry returns an error with partial output preserved (0 waits indefinitely)",
	)
	registerDurationCompletion(command, "timeout", "Disable "+strings.TrimSuffix(timeoutHelp, " (0 disables)"))
	registerDurationCompletion(command, "wait", "Wait indefinitely while draining the response")
	command.Flags().Bool("close-write", true, "half-close the connection write side after input EOF")
	command.Flags().BoolP("duplex", "d", true, "keep sending input after the peer closes its write side")
	command.Flags().BoolP("verbose", "v", false, "write connection details to stderr")
	command.Args = networkAddressArgs(command.Args, allowEmptyHost)
	command.ValidArgsFunction = cobra.NoFileCompletions
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

func addCommandShape(command *cobra.Command, shape string) {
	if command.Annotations == nil {
		command.Annotations = make(map[string]string)
	}
	command.Annotations[commandShapeAnnotationPrefix+shape] = "true"
}

func commandHasShape(command *cobra.Command, shape string) bool {
	return command.Annotations[commandShapeAnnotationPrefix+shape] == "true"
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

func registerDurationCompletion(command *cobra.Command, name, zeroDescription string) {
	if err := command.RegisterFlagCompletionFunc(
		name,
		func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			completions := make([]string, 0, len(durationCompletionValues))
			for _, candidate := range durationCompletionValues {
				if strings.HasPrefix(candidate.value, toComplete) {
					description := candidate.description
					if candidate.value == "0" {
						description = zeroDescription
					}
					completions = append(completions, candidate.value+"\t"+description)
				}
			}
			return completions, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveKeepOrder
		},
	); err != nil {
		panic(err)
	}
}

func registerDescribedFlagCompletion(
	command *cobra.Command,
	name string,
	values func() []string,
	descriptions map[string]string,
) {
	if err := command.RegisterFlagCompletionFunc(
		name,
		func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return filterDescribedCompletions(completionsWithDescriptions(values(), descriptions), toComplete), cobra.ShellCompDirectiveNoFileComp
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
