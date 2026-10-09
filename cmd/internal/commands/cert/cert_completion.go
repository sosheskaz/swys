// Package cert constructs X.509 command operations and their completions.
package cert

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/tlsconfig"
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
	certDNSFlagName          = "dns"
)

func registerCertificateIdentityCompletions(command *cobra.Command) {
	mustRegisterCertificateCompletion(command, "subject", completeCertificateSubject)
	for _, name := range []string{certDNSFlagName, "ip"} {
		mustRegisterCertificateCompletion(command, name, cobra.NoFileCompletions)
	}
	mustRegisterCertificateCompletion(command, tlsconfig.KeyFlagName, completeCertificateArtifact(tlsconfig.KeyFlagName))
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
		if mode, ok := certificateCompletionMode(command); ok && !mode.artifactAllowed(name) {
			return nil, cobra.ShellCompDirectiveNoFileComp
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
	if command.Name() == certVerifyCommandName || command.Name() == certInspectCommandName {
		path, err := command.Flags().GetString("input")
		if err != nil || path == "" || path == "-" {
			return true
		}
	}

	sources := []string{tlsconfig.CertFlagName, tlsconfig.KeyFlagName, csrFlagName, issuerCertFlagName, issuerKeyFlagName, "ca", certIntermediatesFlagName}
	for _, name := range sources {
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

func prepareCertificateCompletion(completionCmd *cobra.Command, args []string, create *cobra.Command) {
	if (completionCmd.Name() != cobra.ShellCompRequestCmd && completionCmd.Name() != cobra.ShellCompNoDescRequestCmd) || len(args) == 0 {
		return
	}
	completedArgs := args[:len(args)-1]
	actual, _, err := completionCmd.Root().Find(completedArgs)
	if err != nil || actual != create {
		return
	}
	probeRoot := commandio.NewProbeRoot()
	probeRoot.AddCommand(NewCommand(commandio.NewLifecycle()))
	probe, probeArgs, err := probeRoot.Find(completedArgs)
	if err != nil || probe.ParseFlags(probeArgs) != nil {
		return
	}
	mode, ok := certificateCompletionMode(probe)
	if !ok {
		return
	}
	create.Flags().Lookup(tlsconfig.KeyFlagName).Hidden = !mode.artifactAllowed(tlsconfig.KeyFlagName)
	create.Flags().Lookup(csrFlagName).Hidden = !mode.artifactAllowed(csrFlagName)
	create.Flags().Lookup("ca").Hidden = !mode.caAllowed()
	for _, name := range []string{certDNSFlagName, "ip", issuerCertFlagName, issuerKeyFlagName, certServerOnlyFlagName, certClientOnlyFlagName} {
		create.Flags().Lookup(name).Hidden = mode.isCA
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
			conflict = !mode.caAllowed()
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

func (mode *certificateCompletionModeState) caAllowed() bool {
	return mode.csr == "" && !mode.hasLeafOptions()
}

func (mode *certificateCompletionModeState) artifactAllowed(name string) bool {
	switch name {
	case tlsconfig.KeyFlagName:
		return mode.csr == ""
	case csrFlagName:
		return mode.key == "" && !mode.isCA
	case issuerCertFlagName, issuerKeyFlagName:
		return !mode.isCA
	default:
		return true
	}
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
	mode.key, err = command.Flags().GetString(tlsconfig.KeyFlagName)
	if err != nil {
		return certificateCompletionModeState{}, false
	}
	mode.csr, err = command.Flags().GetString(csrFlagName)
	if err != nil {
		return certificateCompletionModeState{}, false
	}
	mode.dnsNames, err = command.Flags().GetStringArray(certDNSFlagName)
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

func prepareCertificateArtifactEncodingCompletion(completionCmd *cobra.Command, args []string) {
	if (completionCmd.Name() != cobra.ShellCompRequestCmd && completionCmd.Name() != cobra.ShellCompNoDescRequestCmd) || len(args) == 0 {
		return
	}
	completed := args[:len(args)-1]
	actual, _, err := completionCmd.Root().Find(completed)
	if err != nil {
		return
	}
	switch actual.Name() {
	case "create", csrFlagName, "match", certVerifyCommandName, certInspectCommandName:
	default:
		return
	}
	// Probe flags without reading files or mutating the target command's parsed state.
	probeRoot := commandio.NewProbeRoot()
	probeRoot.AddCommand(NewCommand(commandio.NewLifecycle()))
	probe, probeArgs, err := probeRoot.Find(completed)
	if err != nil {
		return
	}
	if !parseCertificateCompletionFlags(probe, probeArgs) {
		return
	}

	for _, name := range []string{"cert", "key", csrFlagName, "issuer-cert", "issuer-key", "ca", certIntermediatesFlagName} {
		if flag := actual.Flags().Lookup(name + "-encoding"); flag != nil {
			flag.Hidden = !certificateArtifactEncodingApplicable(probe, name)
			if probe.Name() != certVerifyCommandName && probe.Name() != certInspectCommandName {
				source, err := probe.Flags().GetString(name)
				if err == nil && source == "-" && probe.Flags().Changed(name+"-encoding") {
					actual.Flags().Lookup(commandio.InputEncodingFlagName).Hidden = true
				}
			}
		}
	}
}

func parseCertificateCompletionFlags(probe *cobra.Command, probeArgs []string) bool {
	// The final flag may be waiting for the value being completed.
	if len(probeArgs) > 0 {
		last := probeArgs[len(probeArgs)-1]
		if strings.HasPrefix(last, "--") && !strings.Contains(last, "=") {
			if flag := probe.Flags().Lookup(strings.TrimPrefix(last, "--")); flag != nil && flag.NoOptDefVal == "" {
				probeArgs = probeArgs[:len(probeArgs)-1]
			}
		}
	}
	return probe.ParseFlags(probeArgs) == nil
}
