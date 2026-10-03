package commandio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// ConnectTimeoutFlagName and its peers name shared network timing and stream flags.
const (
	ConnectTimeoutFlagName      = "connect-timeout"
	WaitFlagName                = "wait"
	CloseWriteFlagName          = "close-write"
	DuplexFlagName              = "duplex"
	DefaultNetworkTimeout       = 10 * time.Second
	DefaultStreamConnectTimeout = 5 * time.Second
)

// ErrInvalidHostPort identifies a malformed network endpoint.
var (
	ErrInvalidHostPort     = errors.New("invalid host:port")
	ErrInvalidNetworkFlags = errors.New("invalid network flags")
)

// ValidateNetworkTimeout rejects a negative network setup timeout.
func ValidateNetworkTimeout(command *cobra.Command) error {
	timeout, err := command.Flags().GetDuration(ConnectTimeoutFlagName)
	if err != nil {
		return fmt.Errorf("read connect-timeout flag: %w", err)
	}
	if timeout < 0 {
		return fmt.Errorf("%w: --connect-timeout cannot be negative", ErrInvalidNetworkFlags)
	}
	return nil
}

// NetworkCompletion customizes protocol-dependent duration completions.
type NetworkCompletion struct {
	Applicable      func(*cobra.Command, string) bool
	ZeroDescription func(*cobra.Command, string, string) string
}

// NetworkSetupContext applies a setup deadline when timeout is positive.
func NetworkSetupContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout == 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, timeout)
}

// NetworkCommand adds shared network setup behavior and flags.
func NetworkCommand(command *cobra.Command) *cobra.Command {
	AddShape(command, "network")
	command.Flags().DurationP(ConnectTimeoutFlagName, "c", DefaultNetworkTimeout, "TCP setup and TLS handshake timeout (0 disables)")
	RegisterDurationCompletion(command, ConnectTimeoutFlagName, "Disable TCP setup and TLS handshake timeout", NetworkCompletion{})
	command.Args = NetworkAddressArgs(command.Args, false)
	if command.RunE == nil {
		panic(fmt.Sprintf("networkCommand: %q has no RunE; wrap a command that uses RunE, not Run", command.Use))
	}
	originalRunE := command.RunE
	command.RunE = func(cmd *cobra.Command, args []string) error {
		timeout, err := cmd.Flags().GetDuration(ConnectTimeoutFlagName)
		if err != nil {
			return fmt.Errorf("read connect-timeout flag: %w", err)
		}
		originalContext := cmd.Context()
		ctx, cancel := NetworkSetupContext(originalContext, timeout)
		defer cancel()
		defer cmd.SetContext(originalContext)
		cmd.SetContext(ctx)
		return originalRunE(cmd, args)
	}
	return command
}

// StreamNetworkCommandWithTimeout adds stream flags with a setup timeout.
func StreamNetworkCommandWithTimeout(
	command *cobra.Command, defaultTimeout time.Duration, timeoutHelp string,
	allowEmptyHost bool, completions ...NetworkCompletion,
) *cobra.Command {
	var completion NetworkCompletion
	if len(completions) > 0 {
		completion = completions[0]
	}
	AddShape(command, "stream-network")
	AddShape(command, "network")
	command.Flags().DurationP(ConnectTimeoutFlagName, "c", defaultTimeout, timeoutHelp)
	command.Flags().DurationP(WaitFlagName, "w", 0,
		"maximum response drain time after input EOF; expiry returns an error with partial output preserved (0 waits indefinitely)")
	RegisterDurationCompletion(command, ConnectTimeoutFlagName, "Disable "+strings.TrimSuffix(timeoutHelp, " (0 disables)"), completion)
	RegisterDurationCompletion(command, WaitFlagName, "Wait indefinitely while draining the response", completion)
	command.Flags().Bool(CloseWriteFlagName, true, "half-close the connection write side after input EOF")
	command.Flags().Bool(DuplexFlagName, true, "keep sending input after the peer closes its write side")
	command.Flags().BoolP("verbose", "v", false, "write connection details to stderr")
	command.Args = NetworkAddressArgs(command.Args, allowEmptyHost)
	command.ValidArgsFunction = cobra.NoFileCompletions
	if command.RunE == nil {
		panic(fmt.Sprintf("streamNetworkCommand: %q has no RunE; wrap a command that uses RunE, not Run", command.Use))
	}
	return command
}

var durationCompletionValues = []struct{ value, description string }{
	{value: "0"},
	{value: "1s", description: "One second"},
	{value: "5s", description: "Five seconds"},
	{value: "10s", description: "Ten seconds"},
	{value: "30s", description: "Thirty seconds"},
}

// RegisterDurationCompletion offers standard duration choices for a flag.
func RegisterDurationCompletion(command *cobra.Command, name, zeroDescription string, completion NetworkCompletion) {
	if err := command.RegisterFlagCompletionFunc(name, func(cmd *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
		if completion.Applicable != nil && !completion.Applicable(cmd, name) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		values := make([]string, 0, len(durationCompletionValues))
		for _, candidate := range durationCompletionValues {
			if !strings.HasPrefix(candidate.value, prefix) {
				continue
			}
			description := candidate.description
			if candidate.value == "0" {
				description = zeroDescription
				if completion.ZeroDescription != nil {
					description = completion.ZeroDescription(cmd, name, description)
				}
			}
			values = append(values, candidate.value+"\t"+description)
		}
		return values, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveKeepOrder
	}); err != nil {
		panic(err)
	}
}

// NetworkAddressArgs validates positional endpoint arguments.
func NetworkAddressArgs(original cobra.PositionalArgs, allowEmptyHost bool) cobra.PositionalArgs {
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
			address, err = NormalizeListenAddress(address)
			if err != nil {
				return err
			}
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("%w %q: %w", ErrInvalidHostPort, args[0], err)
		}
		if !allowEmptyHost && (host == "" || port == "") {
			return fmt.Errorf("%w %q: host and port are required", ErrInvalidHostPort, args[0])
		}
		if port == "" {
			return fmt.Errorf("%w %q: port is required", ErrInvalidHostPort, args[0])
		}
		return nil
	}
}

// NormalizeListenAddress fills an empty listener host with the wildcard host.
func NormalizeListenAddress(address string) (string, error) {
	if strings.Contains(address, ":") {
		return address, nil
	}
	port, err := strconv.ParseUint(address, 10, 16)
	if err != nil {
		return "", fmt.Errorf("%w %q: bare port must be an integer from 0 to 65535", ErrInvalidHostPort, address)
	}
	return net.JoinHostPort("", strconv.FormatUint(port, 10)), nil
}
