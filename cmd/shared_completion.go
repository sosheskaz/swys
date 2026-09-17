package cmd

import (
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const sharedBase64Encoding = "base64"

var byteEncodingDescriptions = map[string]string{
	byteEncodingRaw:      "unencoded bytes",
	byteEncodingHex:      "hexadecimal",
	sharedBase64Encoding: "standard Base64 with padding",
	"b64":                "alias for base64",
	"base64url":          "URL-safe Base64 (unpadded output)",
	"base32":             "standard Base32 with padding",
}

var structuredFormatDescriptions = map[string]string{
	httpFormatText: "human-readable text",
	"long":         "detailed human-readable text",
	httpFormatJSON: "structured JSON",
	"pem":          "certificate PEM",
	"chain":        "issuer certificates as PEM, excluding the leaf",
	"fullchain":    "leaf and chain certificates as PEM",
}

var outputModeCompletions = []string{
	cobra.CompletionWithDesc("0600", "owner read/write"),
	cobra.CompletionWithDesc("0640", "owner read/write and group read"),
	cobra.CompletionWithDesc("0644", "owner read/write and group/world read"),
}

func completionsWithDescriptions(values []string, descriptions map[string]string) []string {
	completions := make([]string, 0, len(values))
	for _, value := range values {
		description := descriptions[value]
		if description == "" {
			completions = append(completions, value)
			continue
		}
		completions = append(completions, cobra.CompletionWithDesc(value, description))
	}
	return completions
}

func registerSharedCompletions(root *cobra.Command) {
	root.InitDefaultCompletionCmd()
	root.InitDefaultHelpCmd()
	registerCommandCompletions(root)
}

func registerCommandCompletions(command *cobra.Command) {
	command.InitDefaultHelpFlag()
	command.InitDefaultVersionFlag()
	command.Flags().VisitAll(func(flag *pflag.Flag) {
		if _, registered := command.GetFlagCompletionFunc(flag.Name); registered {
			return
		}
		switch {
		case flag.Name == "mode":
			mustRegisterSharedFlagCompletion(command, flag.Name, func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
				return filterDescribedCompletions(outputModeCompletions, toComplete), cobra.ShellCompDirectiveNoFileComp
			})
		case flag.Value.Type() == "bool":
			mustRegisterSharedFlagCompletion(command, flag.Name, func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
				return filterDescribedCompletions([]string{strconv.FormatBool(true), strconv.FormatBool(false)}, toComplete), cobra.ShellCompDirectiveNoFileComp
			})
		}
	})
	for _, child := range command.Commands() {
		registerCommandCompletions(child)
	}
}

func mustRegisterSharedFlagCompletion(command *cobra.Command, name string, completion cobra.CompletionFunc) {
	if err := command.RegisterFlagCompletionFunc(name, completion); err != nil {
		panic(err)
	}
}

func filterDescribedCompletions(values []string, prefix string) []string {
	matches := make([]string, 0, len(values))
	for _, value := range values {
		candidate, _, _ := strings.Cut(value, "\t")
		if strings.HasPrefix(candidate, prefix) {
			matches = append(matches, value)
		}
	}
	return matches
}
