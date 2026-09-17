package cmd

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	netInsecureFlagName = "insecure"
	netSystemCAFlagName = "system-ca"
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
	if err := command.RegisterFlagCompletionFunc("alpn", completeALPN); err != nil {
		panic(err)
	}
}

func completeALPN(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
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

type completionValue struct {
	pflag.Value
	afterSet func()
}

// Set delegates parsing before refreshing flags hidden only from completion.
func (value completionValue) Set(input string) error {
	if err := value.Value.Set(input); err != nil {
		return err //nolint:wrapcheck // Preserve the underlying flag parser's error text.
	}
	value.afterSet()
	return nil
}

func configureTLSConnectFlagCompletion(command *cobra.Command) {
	update := func() {
		if !networkCompletionRequested(command) {
			return
		}
		insecure := command.Flags().Lookup(netInsecureFlagName).Value.String() != completionBoolFalse
		ca := command.Flags().Lookup(tlsCAFlagName).Value.String()
		systemCA := command.Flags().Lookup(netSystemCAFlagName).Value.String() != completionBoolFalse
		command.Flags().Lookup(netInsecureFlagName).Hidden = ca != "" || systemCA
		command.Flags().Lookup(tlsCAFlagName).Hidden = insecure
		command.Flags().Lookup(netSystemCAFlagName).Hidden = insecure
	}
	for _, name := range []string{tlsCAFlagName, netSystemCAFlagName, netInsecureFlagName} {
		flag := command.Flags().Lookup(name)
		flag.Value = completionValue{Value: flag.Value, afterSet: update}
	}
	if err := command.RegisterFlagCompletionFunc(tlsCAFlagName, func(cmd *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		insecure := cmd.Flags().Lookup(netInsecureFlagName).Value.String() != completionBoolFalse
		if insecure {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveDefault
	}); err != nil {
		panic(err)
	}
	for _, name := range []string{netSystemCAFlagName, netInsecureFlagName} {
		if err := command.RegisterFlagCompletionFunc(name, completeTLSBoolean(name)); err != nil {
			panic(err)
		}
	}
}

func completeTLSBoolean(name string) cobra.CompletionFunc {
	return func(cmd *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
		insecure := cmd.Flags().Lookup(netInsecureFlagName).Value.String() != completionBoolFalse
		ca := cmd.Flags().Lookup(tlsCAFlagName).Value.String()
		systemCA := cmd.Flags().Lookup(netSystemCAFlagName).Value.String() != completionBoolFalse
		conflict := name == netSystemCAFlagName && insecure || name == netInsecureFlagName && (ca != "" || systemCA)
		var values []string
		for _, value := range []string{completionBoolTrue, completionBoolFalse} {
			if (!conflict || value == completionBoolFalse) && strings.HasPrefix(value, prefix) {
				values = append(values, value)
			}
		}
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

func networkCompletionRequested(command *cobra.Command) bool {
	for _, child := range command.Root().Commands() {
		if child.Name() == cobra.ShellCompRequestCmd {
			return true
		}
	}
	return false
}
