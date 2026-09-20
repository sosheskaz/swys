package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var certificateDayCompletions = []string{
	cobra.CompletionWithDesc("1", "One day"),
	cobra.CompletionWithDesc("7", "Seven days"),
	cobra.CompletionWithDesc("30", "Thirty days (default for leaf certificates)"),
	cobra.CompletionWithDesc("90", "Ninety days"),
	cobra.CompletionWithDesc("365", "365 days (default for certificate authorities)"),
}

const (
	certServerOnlyFlagName   = "server-only"
	certificateSubjectPrefix = "CN="
	certClientOnlyFlagName   = "client-only"
)

func registerCertificateIdentityCompletions(command *cobra.Command) {
	mustRegisterCertificateCompletion(command, "subject", completeCertificateSubject)
	for _, name := range []string{dnsCommandName, "ip"} {
		mustRegisterCertificateCompletion(command, name, cobra.NoFileCompletions)
	}
	mustRegisterCertificateCompletion(command, tlsKeyFlagName, completeCertificateArtifact(tlsKeyFlagName))
	command.ValidArgsFunction = cobra.NoFileCompletions
}

func registerCertificateCreateCompletions(command *cobra.Command) {
	mustRegisterCertificateCompletion(command, "days", func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return completionPrefixMatches(certificateDayCompletions, toComplete), cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveKeepOrder
	})
	for _, name := range []string{issuerCertFlagName, issuerKeyFlagName, csrFlagName} {
		mustRegisterCertificateCompletion(command, name, completeCertificateArtifact(name))
	}
	for _, name := range []string{"ca", certServerOnlyFlagName, certClientOnlyFlagName} {
		mustRegisterCertificateCompletion(command, name, completeCertificateBoolean(name))
	}
	configureCertificateModeFlagCompletion(command)
}

func mustRegisterCertificateCompletion(command *cobra.Command, name string, completion cobra.CompletionFunc) {
	if err := command.RegisterFlagCompletionFunc(name, completion); err != nil {
		panic(err)
	}
}

func completeCertificateSubject(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(toComplete) > len(certificateSubjectPrefix) || certificateSubjectPrefix[:len(toComplete)] != toComplete {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return []string{cobra.CompletionWithDesc(certificateSubjectPrefix, "X.509 common name")},
		cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
}

func completeCertificateArtifact(name string) cobra.CompletionFunc {
	return func(command *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if name == issuerCertFlagName || name == issuerKeyFlagName || name == csrFlagName {
			if mode, ok := certificateCompletionMode(command); ok && mode.isCA {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
		}
		values, directoriesOnly := completeCertificatePaths(toComplete)
		if (toComplete == "" || toComplete == "-") && !certificateStdinOwnedByOtherFlag(command, name) {
			values = append([]string{cobra.CompletionWithDesc("-", "Read from stdin")}, values...)
			directoriesOnly = false
		}
		directive := cobra.ShellCompDirectiveNoFileComp
		if len(values) != 0 && directoriesOnly {
			directive |= cobra.ShellCompDirectiveNoSpace
		}
		return values, directive
	}
}

func completeCertificatePaths(prefix string) ([]string, bool) {
	directory, base := filepath.Split(prefix)
	readDirectory := directory
	if readDirectory == "" {
		readDirectory = "."
	}
	entries, err := os.ReadDir(readDirectory)
	if err != nil {
		return nil, false
	}
	values := make([]string, 0, len(entries))
	directoriesOnly := true
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), base) {
			continue
		}
		value := directory + entry.Name()
		isDirectory := entry.IsDir()
		if entry.Type()&os.ModeSymlink != 0 {
			if info, err := os.Stat(filepath.Join(readDirectory, entry.Name())); err == nil {
				isDirectory = info.IsDir()
			}
		}
		if isDirectory {
			value += string(filepath.Separator)
		} else {
			directoriesOnly = false
		}
		values = append(values, value)
	}
	slices.Sort(values)
	return values, len(values) != 0 && directoriesOnly
}

func certificateStdinOwnedByOtherFlag(command *cobra.Command, completing string) bool {
	for _, name := range []string{tlsKeyFlagName, csrFlagName, issuerCertFlagName, issuerKeyFlagName} {
		if name == completing || command.Flags().Lookup(name) == nil {
			continue
		}
		value, err := command.Flags().GetString(name)
		if err == nil && value == "-" {
			return true
		}
	}
	return false
}

func completionPrefixMatches(values []string, prefix string) []string {
	matches := make([]string, 0, len(values))
	for _, value := range values {
		candidate := strings.SplitN(value, "\t", 2)[0]
		if strings.HasPrefix(candidate, prefix) {
			matches = append(matches, value)
		}
	}
	return matches
}

type certificateCompletionValue struct {
	pflag.Value
	afterSet func()
}

// Set delegates parsing and refreshes completion-only flag visibility.
func (value certificateCompletionValue) Set(input string) error {
	if err := value.Value.Set(input); err != nil {
		return err //nolint:wrapcheck // Preserve the underlying flag parser's error text.
	}
	value.afterSet()
	return nil
}

type certificateCompletionBoolValue struct {
	certificateCompletionValue
}

// IsBoolFlag preserves pflag's optional-value behavior for wrapped booleans.
func (certificateCompletionBoolValue) IsBoolFlag() bool { return true }

type certificateCompletionSliceValue struct {
	certificateCompletionValue
	pflag.SliceValue
}

// Append preserves repeated slice-flag parsing and refreshes visibility.
func (value certificateCompletionSliceValue) Append(input string) error {
	if err := value.SliceValue.Append(input); err != nil {
		return err //nolint:wrapcheck // Preserve the underlying flag parser's error text.
	}
	value.afterSet()
	return nil
}

// Replace preserves slice-flag replacement and refreshes visibility.
func (value certificateCompletionSliceValue) Replace(inputs []string) error {
	if err := value.SliceValue.Replace(inputs); err != nil {
		return err //nolint:wrapcheck // Preserve the underlying flag parser's error text.
	}
	value.afterSet()
	return nil
}

func configureCertificateModeFlagCompletion(command *cobra.Command) {
	update := func() {
		if !certificateCompletionRequested(command) {
			return
		}
		mode, ok := certificateCompletionMode(command)
		if !ok {
			return
		}
		command.Flags().Lookup(tlsKeyFlagName).Hidden = mode.csr != ""
		command.Flags().Lookup(csrFlagName).Hidden = mode.key != "" || mode.isCA
		command.Flags().Lookup("ca").Hidden = mode.hasLeafOptions() || mode.csr != ""
		for _, name := range []string{dnsCommandName, "ip", issuerCertFlagName, issuerKeyFlagName, certServerOnlyFlagName, certClientOnlyFlagName} {
			command.Flags().Lookup(name).Hidden = mode.isCA
		}
	}
	for _, name := range []string{tlsKeyFlagName, csrFlagName, issuerCertFlagName, issuerKeyFlagName} {
		flag := command.Flags().Lookup(name)
		flag.Value = certificateCompletionValue{Value: flag.Value, afterSet: update}
	}
	for _, name := range []string{"ca", certServerOnlyFlagName, certClientOnlyFlagName} {
		flag := command.Flags().Lookup(name)
		flag.Value = certificateCompletionBoolValue{certificateCompletionValue{Value: flag.Value, afterSet: update}}
	}
	for _, name := range []string{dnsCommandName, "ip"} {
		flag := command.Flags().Lookup(name)
		sliceValue, ok := flag.Value.(pflag.SliceValue)
		if !ok {
			panic("certificate completion expected a slice flag: " + name)
		}
		flag.Value = certificateCompletionSliceValue{
			certificateCompletionValue: certificateCompletionValue{Value: flag.Value, afterSet: update},
			SliceValue:                 sliceValue,
		}
		// pflag recognizes "[]" as zero only for its concrete slice types. The
		// wrapper preserves the value but needs the generic zero spelling for help.
		if flag.DefValue == "[]" {
			flag.DefValue = ""
		}
	}
}

func completeCertificateBoolean(name string) cobra.CompletionFunc {
	return func(command *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
		mode, ok := certificateCompletionMode(command)
		if !ok {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		conflict := mode.isCA
		switch name {
		case "ca":
			conflict = mode.hasLeafOptions()
		case certServerOnlyFlagName:
			if command.Flags().Changed(certClientOnlyFlagName) {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
		case certClientOnlyFlagName:
			if command.Flags().Changed(certServerOnlyFlagName) {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
		}
		var values []string
		for _, value := range []bool{true, false} {
			candidate := strconv.FormatBool(value)
			if (!conflict || !value) && strings.HasPrefix(candidate, prefix) {
				values = append(values, candidate)
			}
		}
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

type certificateCompletionModeState struct {
	key         string
	csr         string
	issuerCert  string
	issuerKey   string
	dnsNames    []string
	ipAddresses []string
	isCA        bool
	serverOnly  bool
	clientOnly  bool
}

func (mode *certificateCompletionModeState) hasLeafOptions() bool {
	return len(mode.dnsNames) != 0 || len(mode.ipAddresses) != 0 || mode.issuerCert != "" || mode.issuerKey != "" || mode.serverOnly || mode.clientOnly
}

func certificateCompletionMode(command *cobra.Command) (certificateCompletionModeState, bool) {
	mode := certificateCompletionModeState{}
	var err error
	mode.isCA, err = command.Flags().GetBool("ca")
	if err != nil {
		return certificateCompletionModeState{}, false
	}
	mode.key, err = command.Flags().GetString(tlsKeyFlagName)
	if err != nil {
		return certificateCompletionModeState{}, false
	}
	mode.csr, err = command.Flags().GetString(csrFlagName)
	if err != nil {
		return certificateCompletionModeState{}, false
	}
	mode.dnsNames, err = command.Flags().GetStringArray(dnsCommandName)
	if err != nil {
		return certificateCompletionModeState{}, false
	}
	mode.ipAddresses, err = command.Flags().GetStringArray("ip")
	if err != nil {
		return certificateCompletionModeState{}, false
	}
	mode.issuerCert, err = command.Flags().GetString(issuerCertFlagName)
	if err != nil {
		return certificateCompletionModeState{}, false
	}
	mode.issuerKey, err = command.Flags().GetString(issuerKeyFlagName)
	if err != nil {
		return certificateCompletionModeState{}, false
	}
	mode.serverOnly, err = command.Flags().GetBool(certServerOnlyFlagName)
	if err != nil {
		return certificateCompletionModeState{}, false
	}
	mode.clientOnly, err = command.Flags().GetBool(certClientOnlyFlagName)
	if err != nil {
		return certificateCompletionModeState{}, false
	}
	return mode, true
}

func certificateCompletionRequested(command *cobra.Command) bool {
	for _, child := range command.Root().Commands() {
		if child.Name() == cobra.ShellCompRequestCmd || child.Name() == cobra.ShellCompNoDescRequestCmd {
			return true
		}
	}
	return false
}
