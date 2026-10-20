package tlsconfig

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// ALPNFlagName names the comma-separated TLS application protocol list.
const ALPNFlagName = "alpn"

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

// ParseALPN splits a comma-separated protocol list; empty text advertises none.
// Each family supplies its validation error identity as invalid.
func ParseALPN(text string, invalid error) ([]string, error) {
	if text == "" {
		return nil, nil
	}
	protocols := strings.Split(text, ",")
	for _, protocol := range protocols {
		if protocol == "" || protocol != strings.TrimSpace(protocol) || len(protocol) > 255 {
			return nil, fmt.Errorf("%w: --alpn values must be 1-255 bytes with no surrounding whitespace", invalid)
		}
	}
	return protocols, nil
}

// CompleteALPN suggests well-known protocols for the list's final element,
// omitting protocols already listed.
func CompleteALPN(toComplete string) ([]string, cobra.ShellCompDirective) {
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
