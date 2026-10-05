package aes

import (
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
)

func registerAESNoFileFlagCompletion(cmd *cobra.Command, name string) {
	if err := cmd.RegisterFlagCompletionFunc(name, func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		panic(err)
	}
}

var aesCompletionDescriptions = map[string]string{
	wireOpenPGP: "OpenPGP RFC 9580 AES-GCM", wireTink: "Tink AES-GCM-HKDF stream",
	keyFormatAuto: "Detect the key file format", keyFormatRaw: "Raw AES key bytes",
	keyFormatTinkJSON: "Cleartext Tink JSON keyset", keyFormatTinkBinary: "Cleartext Tink binary keyset",
	hashSHA256: "SHA-256 HKDF", hashSHA512: "SHA-512 HKDF",
	"128": "128-bit AES key", "256": "256-bit AES key",
	"true": "Prompt for a password on the controlling terminal",
}

func registerAESValueCompletion(cmd *cobra.Command, name string, values func() []string) {
	if err := cmd.RegisterFlagCompletionFunc(name, func(cmd *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
		if name == passwordFlagName && aesCompletionAnyChanged(cmd.Flags().Changed,
			keyFlagName, keyBase64FlagName, "password-command", "password-env") {

			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		var matches []string
		for _, value := range values() {
			if strings.HasPrefix(value, prefix) && aesCompletionCompatible(cmd, name, value) {
				matches = append(matches, cobra.CompletionWithDesc(value, aesCompletionDescriptions[value]))
			}
		}
		return matches, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		panic(err)
	}
}

// Candidate values replace the flag being completed, including a repeated flag.
// Only declared formats and parameters are known here; key contents stay unread.
func aesCompletionCompatible(cmd *cobra.Command, name, value string) bool {
	text := func(flag string) string {
		if flag == name {
			return value
		}
		v, err := cmd.Flags().GetString(flag)
		if err != nil {
			return ""
		}
		return v
	}
	changed := func(flag string) bool { return flag == name || cmd.Flags().Changed(flag) }
	switch cmd.Name() {
	case "encrypt", commandDecrypt:
		return aesOperationCompletionCompatible(cmd, name, text, changed)
	case commandKeygen:
		return aesKeygenCompletionCompatible(cmd, name, value, text, changed)
	case commandKeyConvert:
		return aesKeyConvertCompletionCompatible(text, changed)
	default:
		return true
	}
}

func aesOperationCompletionCompatible(cmd *cobra.Command, name string, text func(string) string, changed func(string) bool) bool {
	if name != passwordFlagName && cmd.Flags().Changed(passwordFlagName) {
		enabled, err := cmd.Flags().GetBool(passwordFlagName)
		if err != nil || !enabled {
			return false
		}
	}
	if !aesWireCompletionCompatible(cmd, name == passwordFlagName || passwordSelected(cmd), text, changed) {
		return false
	}
	format := text("key-format")
	if !aesCompletionReaderFormat(format) {
		return false
	}
	if cmd.Flags().Changed(keyBase64FlagName) && changed("key-format") && format != keyFormatRaw {
		return false
	}
	return !changed("key-id") || !cmd.Flags().Changed(keyBase64FlagName) && format != keyFormatRaw
}

func aesCompletionReaderFormat(format string) bool {
	return format == keyFormatAuto || slices.Contains(keyFormatNames(), format)
}

func aesCompletionAnyChanged(changed func(string) bool, names ...string) bool {
	for _, name := range names {
		if changed(name) {
			return true
		}
	}
	return false
}

func aesWireCompletionCompatible(
	cmd *cobra.Command, passwordMode bool, text func(string) string, changed func(string) bool,
) bool {
	tinkOptions := aesCompletionAnyChanged(changed, flagAAD, flagHKDFHash, flagDerivedBits)
	decryptChunk := cmd.Name() == commandDecrypt && changed("chunk-size")
	wire := text("wire-format")
	if passwordMode {
		return !aesCompletionAnyChanged(changed, "key-format", "key-id") && !tinkOptions && !decryptChunk && wire == wireOpenPGP
	}
	if !changed("wire-format") {
		return true
	}
	switch wire {
	case wireOpenPGP:
		return !tinkOptions && !decryptChunk
	case wireTink:
		return !changed("key-id")
	default:
		return false
	}
}

func aesKeyConvertCompletionCompatible(text func(string) string, changed func(string) bool) bool {
	from, to := text("from"), text("to")
	if !aesCompletionReaderFormat(from) || to != "" && !slices.Contains(keyFormatNames(), to) {
		return false
	}
	if changed("key-id") && (from == keyFormatRaw || to != keyFormatRaw && to != "") {
		return false
	}
	tuning := aesCompletionAnyChanged(changed, "chunk-size", flagHKDFHash, flagDerivedBits)
	return !tuning || (from == keyFormatAuto || from == keyFormatRaw) && to != keyFormatRaw
}

func aesKeygenCompletionCompatible(
	cmd *cobra.Command, name, value string, text func(string) string, changed func(string) bool,
) bool {
	tuning := aesCompletionAnyChanged(changed, "chunk-size", flagHKDFHash, flagDerivedBits)
	format := text("key-format")
	if !slices.Contains(keyFormatNames(), format) || format == keyFormatRaw && tuning {
		return false
	}
	integer := func(flag string) (int, error) {
		if flag == name {
			return strconv.Atoi(value)
		}
		return cmd.Flags().GetInt(flag)
	}
	bits, err := integer("bits")
	if err != nil {
		return false
	}
	derived, err := integer(flagDerivedBits)
	return err == nil && (derived == 0 || derived <= bits)
}

// prepareAESCompletion hides flags incompatible with the selected credential
// and wire or key format.
func prepareAESCompletion(completionCmd *cobra.Command, args []string) {
	if (completionCmd.Name() != cobra.ShellCompRequestCmd && completionCmd.Name() != cobra.ShellCompNoDescRequestCmd) || len(args) == 0 {
		return
	}
	probe := commandio.NewProbeRoot()
	probe.AddCommand(NewCommand(commandio.NewLifecycle()))
	parsed, remaining, err := probe.Find(args[:len(args)-1])
	if err != nil || !isAESCompletionCommand(parsed) {
		return
	}
	if err := parsed.ParseFlags(remaining); err != nil {
		return
	}
	actual, _, err := completionCmd.Root().Find(args[:len(args)-1])
	if err != nil || !isAESCompletionCommand(actual) {
		return
	}
	hideIncompatibleAESFlags(parsed, actual)
}

func hideIncompatibleAESFlags(parsed, actual *cobra.Command) {
	hide := func(names ...string) {
		for _, name := range names {
			if flag := actual.Flags().Lookup(name); flag != nil {
				flag.Hidden = true
			}
		}
	}
	if parsed.Name() == commandKeygen || parsed.Name() == commandKeyConvert {
		hideAESKeyCommandFlags(parsed, hide)
		return
	}
	wire, err := parsed.Flags().GetString("wire-format")
	if err != nil {
		return
	}
	if !aesCompletionCompatible(parsed, passwordFlagName, "true") {
		hide(passwordSources...)
	}
	if passwordSelected(parsed) {
		hide("key-format", "key-id", flagAAD, flagHKDFHash, flagDerivedBits)
		if parsed.Name() == commandDecrypt {
			hide("chunk-size")
		}
		return
	}
	hide(kdfMemoryFlag, kdfPassesFlag, kdfParallelismFlag)
	format, err := parsed.Flags().GetString("key-format")
	if err != nil {
		return
	}
	if parsed.Flags().Changed(keyBase64FlagName) || format == keyFormatRaw {
		hide("key-id")
	}
	if wire == wireOpenPGP {
		hide(flagAAD, flagHKDFHash, flagDerivedBits)
		if parsed.Name() == commandDecrypt {
			hide("chunk-size")
		}
	}
	if wire == wireTink {
		hide("key-id")
	}
}

func hideAESKeyCommandFlags(parsed *cobra.Command, hide func(...string)) {
	if parsed.Name() == commandKeygen {
		format, err := parsed.Flags().GetString("key-format")
		if err != nil {
			return
		}
		if format == keyFormatRaw {
			hide("chunk-size", flagHKDFHash, flagDerivedBits)
		}
		return
	}
	if parsed.Name() == commandKeyConvert {
		from, err := parsed.Flags().GetString("from")
		if err != nil {
			return
		}
		to, err := parsed.Flags().GetString("to")
		if err != nil {
			return
		}
		if from == keyFormatRaw || to != keyFormatRaw && to != "" {
			hide("key-id")
		}
		if from != keyFormatAuto && from != keyFormatRaw || to == keyFormatRaw {
			hide("chunk-size", flagHKDFHash, flagDerivedBits)
		}
		return
	}
}

func isAESCompletionCommand(cmd *cobra.Command) bool {
	return cmd != nil && cmd.Parent() != nil && cmd.Parent().Name() == "aes" &&
		(cmd.Name() == "encrypt" || cmd.Name() == commandDecrypt || cmd.Name() == commandKeygen || cmd.Name() == commandKeyConvert)
}
