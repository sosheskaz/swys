// Package net constructs connection and listener commands.
package net

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/tlsconfig"
)

const (
	netInsecureFlagName = "insecure"
	completionBoolTrue  = "true"
	completionBoolFalse = "false"
)

var alpnCompletions = []struct {
	value       string
	description string
}{
	{value: "h2", description: "HTTP/2"},
	{value: "http/1.1", description: "HTTP/1.1"},
	{value: "dot", description: "DNS over TLS"},
	{value: "mqtt", description: "MQTT"},
	{value: "postgresql", description: "PostgreSQL"},
	{value: "imap", description: "IMAP"},
	{value: "pop3", description: "POP3"},
	{value: "acme-tls/1", description: "ACME TLS-ALPN challenge"},
}

func registerALPNCompletion(command *cobra.Command) {
	if err := command.RegisterFlagCompletionFunc(netALPNFlagName, completeALPN); err != nil {
		panic(err)
	}
}

func completeALPN(cmd *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if !netFlagValueCompletionApplicable(cmd, netALPNFlagName) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	prefix := ""
	component := toComplete
	used := make(map[string]struct{})
	if comma := strings.LastIndexByte(toComplete, ','); comma >= 0 {
		prefix = toComplete[:comma+1]
		component = toComplete[comma+1:]
		for value := range strings.SplitSeq(toComplete[:comma], ",") {
			used[value] = struct{}{}
		}
	}

	completions := make([]string, 0, len(alpnCompletions))
	for _, candidate := range alpnCompletions {
		if _, duplicate := used[candidate.value]; duplicate || !strings.HasPrefix(candidate.value, component) {
			continue
		}
		completions = append(completions, prefix+candidate.value+"\t"+candidate.description)
	}
	return completions, cobra.ShellCompDirectiveNoSpace |
		cobra.ShellCompDirectiveNoFileComp |
		cobra.ShellCompDirectiveKeepOrder
}

func registerNoFileFlagCompletion(command *cobra.Command, name string) {
	if err := command.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions); err != nil {
		panic(err)
	}
}

func configureTLSConnectFlagCompletion(command *cobra.Command) {
	if err := command.RegisterFlagCompletionFunc(tlsconfig.CAFlagName, func(cmd *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		if !netFlagValueCompletionApplicable(cmd, tlsconfig.CAFlagName) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		if !netTLSConnectCompletionAllowed(cmd, tlsconfig.CAFlagName) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveDefault
	}); err != nil {
		panic(err)
	}
	for _, name := range []string{tlsconfig.SystemCAFlagName, netInsecureFlagName} {
		if err := command.RegisterFlagCompletionFunc(name, completeTLSBoolean(name)); err != nil {
			panic(err)
		}
	}
}

func updateTLSConnectCompletionFlags(command, values *cobra.Command) {
	for _, name := range []string{netInsecureFlagName, tlsconfig.CAFlagName, tlsconfig.SystemCAFlagName} {
		command.Flags().Lookup(name).Hidden = !netTLSConnectCompletionAllowed(values, name)
	}
}

func netTLSConnectCompletionAllowed(command *cobra.Command, name string) bool {
	insecure := command.Flags().Lookup(netInsecureFlagName).Value.String() != completionBoolFalse
	ca := command.Flags().Lookup(tlsconfig.CAFlagName).Value.String()
	systemCA := command.Flags().Lookup(tlsconfig.SystemCAFlagName).Value.String() != completionBoolFalse
	if name == netInsecureFlagName {
		return ca == "" && !systemCA
	}
	return !insecure
}

func completeTLSBoolean(name string) cobra.CompletionFunc {
	return func(cmd *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
		if !netFlagValueCompletionApplicable(cmd, name) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		conflict := !netTLSConnectCompletionAllowed(cmd, name)
		var values []string
		for _, value := range []string{completionBoolTrue, completionBoolFalse} {
			if (!conflict || value == completionBoolFalse) && strings.HasPrefix(value, prefix) {
				values = append(values, value)
			}
		}
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

func configureNetProtocolCompletion(command *cobra.Command, listen bool) {
	// The initial visibility is the default TCP selection. Help restores the full
	// documented flag union before rendering.
	setNetProtocolFlagVisibility(command, netProtocolTCP, listen)
}

func prepareNetCompletion(completionCmd *cobra.Command, args []string) {
	if (completionCmd.Name() != cobra.ShellCompRequestCmd && completionCmd.Name() != cobra.ShellCompNoDescRequestCmd) || len(args) == 0 {
		return
	}
	completedArgs := args[:len(args)-1]
	actual, _, err := completionCmd.Root().Find(completedArgs)
	if err != nil || !IsProtocolCommand(actual) {
		return
	}
	probe := netCompletionProbe(completedArgs)
	if probe == nil {
		return
	}
	protocol, err := networkProtocolFromCommand(probe)
	if err != nil {
		return
	}
	setNetProtocolFlagVisibility(actual, protocol, probe.Name() != netConnectCommandName)
	actual.Flag(netProtocolUDP).Hidden = !netUDPCompletionAllowed(probe)
	if probe.Name() == netConnectCommandName && protocol == netProtocolTLS {
		updateTLSConnectCompletionFlags(actual, probe)
	}
	actual.Flag("input").Hidden = netReceiveOnlySelected(probe)
	if netReceiveOnlySelected(probe) {
		actual.Flag(netDuplexFlagName).Hidden = true
	}
	if flag := actual.Flag(netRecvOnlyFlagName); flag != nil &&
		(probe.Flags().Changed(netDuplexFlagName) || probe.Flags().Changed("input")) {

		flag.Hidden = true
	}
}

func netCompletionProbe(completedArgs []string) *cobra.Command {
	probeRoot := commandio.NewProbeRoot()
	probeRoot.AddCommand(NewCommand(commandio.NewLifecycle()))
	probe, probeArgs, err := probeRoot.Find(completedArgs)
	if err != nil {
		return nil
	}
	if err := probe.ParseFlags(probeArgs); err != nil {
		if len(probeArgs) == 0 || (probeArgs[len(probeArgs)-1] != "--input" && probeArgs[len(probeArgs)-1] != "-i") {
			return nil
		}
		// Parse normally before treating a trailing input option as unfinished,
		// so a flag-looking path stays a value. Retry without partial parse state.
		probeRoot = commandio.NewProbeRoot()
		probeRoot.AddCommand(NewCommand(commandio.NewLifecycle()))
		probe, probeArgs, err = probeRoot.Find(completedArgs[:len(completedArgs)-1])
		if err != nil || probe.ParseFlags(probeArgs) != nil {
			return nil
		}
	}
	return probe
}

func netReceiveOnlySelected(command *cobra.Command) bool {
	if command.Flags().Lookup(netRecvOnlyFlagName) == nil {
		return false
	}
	value, err := command.Flags().GetBool(netRecvOnlyFlagName)
	return err == nil && value
}

func netUDPCompletionAllowed(command *cobra.Command) bool {
	tls, err := command.Flags().GetBool(netProtocolTLS)
	if err != nil || tls {
		return false
	}
	allowed := true
	command.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Changed && !netProtocolFlagApplicable(command, netProtocolUDP, flag.Name) {
			allowed = false
		}
	})
	return allowed
}

func setNetProtocolFlagVisibility(command *cobra.Command, protocol string, listen bool) {
	command.Flags().Lookup(netProtocolUDP).Hidden = protocol == netProtocolTLS
	command.Flags().Lookup(netProtocolTLS).Hidden = protocol == netProtocolUDP
	for _, name := range []string{
		tlsconfig.CertFlagName, tlsconfig.KeyFlagName, tlsconfig.CAFlagName, tlsconfig.SystemCAFlagName,
		netALPNFlagName, tlsconfig.ServerNameFlagName, netInsecureFlagName,
	} {
		if candidate := command.Flags().Lookup(name); candidate != nil {
			candidate.Hidden = protocol != netProtocolTLS
		}
	}
	for _, name := range []string{netCloseWriteFlagName, netDuplexFlagName, netRecvOnlyFlagName} {
		if candidate := command.Flags().Lookup(name); candidate != nil {
			candidate.Hidden = protocol == netProtocolUDP
		}
	}
	if listen {
		command.Flags().Lookup(netWaitFlagName).Hidden = protocol == netProtocolUDP
	}
}

func netDurationZeroDescription(command *cobra.Command, name, fallback string) string {
	protocol, err := networkProtocolFromCommand(command)
	if err != nil {
		return fallback
	}
	switch name {
	case netWaitFlagName:
		if protocol == netProtocolUDP {
			return "Wait indefinitely for a response datagram"
		}
		return "Wait indefinitely while draining the response"
	case netConnectTimeoutFlagName:
		if command.Name() == netConnectCommandName {
			if protocol == netProtocolUDP {
				return "Disable UDP address resolution and socket setup timeout"
			}
			return "Disable TCP setup and TLS handshake timeout"
		}
		switch protocol {
		case netProtocolUDP:
			return "Disable bind resolution and first datagram timeout"
		case netProtocolTLS:
			return "Disable bind resolution, accept, and TLS handshake timeout"
		default:
			return "Disable bind resolution and accept timeout"
		}
	}
	return fallback
}

func netFlagValueCompletionApplicable(cmd *cobra.Command, name string) bool {
	if !commandio.HasShape(cmd, netProtocolShape) {
		return true
	}
	protocol, err := networkProtocolFromCommand(cmd)
	if err != nil || !netProtocolFlagApplicable(cmd, protocol, name) {
		return false
	}
	return name != netDuplexFlagName || !netReceiveOnlySelected(cmd)
}

// Cobra's default filename and boolean value completions do not inspect flag
// visibility. Register callbacks for applicable protocol flags without an
// existing specialized callback.
func registerNetDefaultValueCompletions(command *cobra.Command) {
	for _, name := range []string{
		tlsconfig.CertFlagName, tlsconfig.KeyFlagName, tlsconfig.CAFlagName, tlsconfig.SystemCAFlagName,
		netInsecureFlagName, netCloseWriteFlagName, netDuplexFlagName, netRecvOnlyFlagName, netProtocolUDP,
	} {
		flag := command.Flags().Lookup(name)
		if flag == nil {
			continue
		}
		if _, registered := command.GetFlagCompletionFunc(name); registered {
			continue
		}
		if err := command.RegisterFlagCompletionFunc(name, func(cmd *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
			if name == netProtocolUDP {
				if !netUDPCompletionAllowed(cmd) {
					return filterNetBooleanCompletions(prefix, completionBoolFalse), cobra.ShellCompDirectiveNoFileComp
				}
				return filterNetBooleanCompletions(prefix, completionBoolTrue, completionBoolFalse), cobra.ShellCompDirectiveNoFileComp
			}
			if !netFlagValueCompletionApplicable(cmd, name) {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			if flag.Value.Type() == "bool" {
				if name == netRecvOnlyFlagName && (cmd.Flags().Changed(netDuplexFlagName) || cmd.Flags().Changed("input")) {
					return filterNetBooleanCompletions(prefix, completionBoolFalse), cobra.ShellCompDirectiveNoFileComp
				}
				return filterNetBooleanCompletions(prefix, completionBoolTrue, completionBoolFalse), cobra.ShellCompDirectiveNoFileComp
			}
			return nil, cobra.ShellCompDirectiveDefault
		}); err != nil {
			panic(err)
		}
	}
}

func filterNetBooleanCompletions(prefix string, candidates ...string) []string {
	var values []string
	for _, value := range candidates {
		if strings.HasPrefix(value, prefix) {
			values = append(values, value)
		}
	}
	return values
}

// ReferenceHelp presents every protocol flag in generated reference help.
func ReferenceHelp(command *cobra.Command, render func()) {
	if !IsProtocolCommand(command) {
		render()
		return
	}
	var hidden []*pflag.Flag
	command.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Hidden {
			hidden = append(hidden, flag)
			flag.Hidden = false
		}
	})
	defer func() {
		for _, flag := range hidden {
			flag.Hidden = true
		}
	}()
	render()
}
