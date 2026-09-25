package net

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/tlsconfig"
)

const (
	defaultNetworkWait          = 5 * time.Second
	defaultStreamConnectTimeout = 5 * time.Second
	networkShape                = "network"
	netProtocolShape            = "net-protocol"
	netProtocolTCP              = "tcp"
	netProtocolUDP              = "udp"
	netProtocolTLS              = "tls"
	netTimeoutFlagName          = "timeout"
	netALPNFlagName             = "alpn"
	netStreamOnlyHelp           = " (TCP/TLS only)"
	netCloseWriteFlagName       = "close-write"
	netDuplexFlagName           = "duplex"
	netRecvOnlyFlagName         = "recv-only"
	netWaitFlagName             = "wait"
	netConnectCommandName       = "connect"
)

func networkProtocolFromCommand(cmd *cobra.Command) (string, error) {
	udp, err := cmd.Flags().GetBool(netProtocolUDP)
	if err != nil {
		return "", fmt.Errorf("read udp flag: %w", err)
	}
	tls, err := cmd.Flags().GetBool(netProtocolTLS)
	if err != nil {
		return "", fmt.Errorf("read tls flag: %w", err)
	}
	if udp && tls {
		return "", fmt.Errorf("%w: --udp and --tls cannot both be enabled", ErrInvalidFlags)
	}
	if udp {
		return netProtocolUDP, nil
	}
	if tls {
		return netProtocolTLS, nil
	}
	return netProtocolTCP, nil
}

func validateNetProtocolFlagsBeforeIO(cmd *cobra.Command) error {
	protocol, err := networkProtocolFromCommand(cmd)
	if err != nil {
		return err
	}
	for _, name := range []string{
		tlsconfig.CertFlagName, tlsconfig.KeyFlagName, tlsconfig.CAFlagName,
		tlsconfig.SystemCAFlagName, netALPNFlagName, tlsconfig.ServerNameFlagName, netInsecureFlagName,
		netCloseWriteFlagName, netDuplexFlagName, netRecvOnlyFlagName, netWaitFlagName,
	} {
		if !cmd.Flags().Changed(name) || netProtocolFlagApplicable(cmd, protocol, name) {
			continue
		}
		hint := ""
		if isNetTLSFlag(name) {
			hint = " (TLS flags require --tls)"
		}
		return fmt.Errorf("%w: --%s is not applicable to %s%s", ErrInvalidFlags, name, protocol, hint)
	}
	if protocol == netProtocolTLS {
		if cmd.Name() == "listen" {
			return validateTLSListenFlagsBeforeIO(cmd)
		}
		return validateTLSFlagsBeforeIO(cmd)
	}
	return nil
}

func isNetTLSFlag(name string) bool {
	switch name {
	case tlsconfig.CertFlagName, tlsconfig.KeyFlagName, tlsconfig.CAFlagName,
		tlsconfig.SystemCAFlagName, netALPNFlagName, tlsconfig.ServerNameFlagName, netInsecureFlagName:
		return true
	default:
		return false
	}
}

func netProtocolFlagApplicable(cmd *cobra.Command, protocol, name string) bool {
	if isNetTLSFlag(name) {
		return protocol == netProtocolTLS
	}
	if protocol != netProtocolUDP {
		return true
	}
	switch name {
	case netCloseWriteFlagName, netDuplexFlagName, netRecvOnlyFlagName:
		return false
	case netWaitFlagName:
		return cmd.Name() == netConnectCommandName
	default:
		return true
	}
}

func netProtocolAddressArgs(original cobra.PositionalArgs, listen bool) cobra.PositionalArgs {
	validated := commandio.NetworkAddressArgs(original, listen)
	return func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			switch args[0] {
			case netProtocolTCP, netProtocolUDP, netProtocolTLS:
				selector := ""
				if args[0] != netProtocolTCP {
					selector = "--" + args[0] + " "
				}
				return fmt.Errorf("%w: use net %s %s<endpoint>", ErrInvalidFlags, cmd.Name(), selector)
			}
		}
		if _, err := networkProtocolFromCommand(cmd); err != nil {
			return err
		}
		return validated(cmd, args)
	}
}

func netConnectWait(cmd *cobra.Command) (time.Duration, error) {
	if !cmd.Flags().Changed(netWaitFlagName) {
		protocol, err := networkProtocolFromCommand(cmd)
		if err != nil {
			return 0, err
		}
		if protocol == netProtocolUDP {
			return defaultNetworkWait, nil
		}
	}
	wait, err := cmd.Flags().GetDuration(netWaitFlagName)
	if err != nil {
		return 0, fmt.Errorf("read wait flag: %w", err)
	}
	return wait, nil
}

// ErrInvalidFlags identifies incompatible network flag combinations.
var ErrInvalidFlags = commandio.ErrInvalidNetworkFlags

func validateNetCommand(cmd *cobra.Command) error {
	if err := validateNetFlagsBeforeIO(cmd); err != nil {
		return fmt.Errorf("validate network flags: %w", err)
	}
	return nil
}

// IsProtocolCommand reports whether command exposes the net transport selector.
func IsProtocolCommand(cmd *cobra.Command) bool { return commandio.HasShape(cmd, netProtocolShape) }
