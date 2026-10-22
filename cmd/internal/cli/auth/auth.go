// Package auth formats an Authorization credential from dedicated, mutually exclusive flags.
package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sosheskaz/swys/cmd/internal/cli/artifact"
	"github.com/sosheskaz/swys/cmd/internal/cli/tlsconfig"
)

// Shared flag names keep credential selection identical across request families.
const (
	BearerFlagName     = "auth-bearer"
	BearerFileFlagName = "auth-bearer-file"
	BearerEnvFlagName  = "auth-bearer-env"
	BasicFlagName      = "auth-basic"
	BasicFileFlagName  = "auth-basic-file"
	BasicEnvFlagName   = "auth-basic-env"
	// CleartextFlagName permits a credential on a transport without TLS.
	CleartextFlagName = "insecure-cleartext-auth"
)

// MaxBytes bounds credential files and variables like AES passwords.
const MaxBytes = 64 << 10

var sourceFlagNames = []string{
	BearerFlagName, BearerFileFlagName, BearerEnvFlagName,
	BasicFlagName, BasicFileFlagName, BasicEnvFlagName,
}

// FileFlagNames lists the path-valued sources for same-file and completion checks.
var FileFlagNames = []string{BearerFileFlagName, BasicFileFlagName}

// AddFlags registers credential flags on the family's flag set.
// Exclusivity is enforced by Validate; the Cobra group only shapes completion.
func AddFlags(cmd *cobra.Command, flags *pflag.FlagSet) {
	flags.String(BearerFlagName, "", "send Authorization: Bearer TOKEN (visible to other local users)")
	flags.String(BearerFileFlagName, "", "read the bearer token from this file; - reads stdin")
	flags.String(BearerEnvFlagName, "", "read the bearer token from this named environment variable")
	flags.String(BasicFlagName, "", "send Basic USER:PASSWORD credentials (visible to other local users)")
	flags.String(BasicFileFlagName, "", "read Basic USER:PASSWORD credentials from this file; - reads stdin")
	flags.String(BasicEnvFlagName, "", "read Basic USER:PASSWORD credentials from this named environment variable")
	flags.Bool(CleartextFlagName, false, "permit --auth-* credentials without TLS")
	for _, name := range FileFlagNames {
		if err := cobra.MarkFlagFilename(flags, name); err != nil {
			panic(err)
		}
	}
	for _, name := range []string{BearerFlagName, BearerEnvFlagName, BasicFlagName, BasicEnvFlagName} {
		if err := cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions); err != nil {
			panic(err)
		}
	}
	cmd.MarkFlagsMutuallyExclusive(sourceFlagNames...)
}

// Selected names the credential source flag in use, if any.
func Selected(flags *pflag.FlagSet) (string, bool) {
	for _, name := range sourceFlagNames {
		if flag := flags.Lookup(name); flag != nil && flag.Changed {
			return name, true
		}
	}
	return "", false
}

// UsesStdin reports an exact dash credential file without touching input.
func UsesStdin(flags *pflag.FlagSet) bool {
	source, ok := Selected(flags)
	return ok && isFileSource(source) && flags.Lookup(source).Value.String() == "-"
}

// Validate checks selection, transport, and stdin ownership before any credential I/O.
// cleartext reports a request target without TLS. payloadStdin reports the family's
// effective payload ownership; TLS artifacts are checked here.
func Validate(flags *pflag.FlagSet, cleartext, payloadStdin bool, invalid error) error {
	selected := 0
	for _, name := range sourceFlagNames {
		if flag := flags.Lookup(name); flag != nil && flag.Changed {
			selected++
		}
	}
	if selected > 1 {
		return fmt.Errorf("%w: choose one of --%s", invalid, strings.Join(sourceFlagNames, ", --"))
	}
	source, ok := Selected(flags)
	allowCleartext := boolFlag(flags, CleartextFlagName)
	if allowCleartext && !ok {
		return fmt.Errorf("%w: --%s requires an --auth-* credential", invalid, CleartextFlagName)
	}
	if allowCleartext && !cleartext {
		return fmt.Errorf("%w: --%s requires a cleartext target", invalid, CleartextFlagName)
	}
	if !ok {
		return nil
	}
	if cleartext && !allowCleartext && !boolFlag(flags, tlsconfig.InsecureFlagName) {
		return fmt.Errorf("%w: --%s without TLS requires --%s", invalid, source, CleartextFlagName)
	}
	return validateSource(flags, source, payloadStdin, invalid)
}

func validateSource(flags *pflag.FlagSet, source string, payloadStdin bool, invalid error) error {
	value := flags.Lookup(source).Value.String()
	switch {
	case isFileSource(source) && value == "":
		return fmt.Errorf("%w: --%s requires a path or -", invalid, source)
	case isEnvSource(source) && value == "":
		return fmt.Errorf("%w: --%s requires a variable name", invalid, source)
	case isFileSource(source) && value == "-":
		if owner := stdinOwner(flags, payloadStdin); owner != "" {
			return fmt.Errorf("%w: --%s and %s cannot both read stdin", invalid, source, owner)
		}
	}
	return nil
}

func stdinOwner(flags *pflag.FlagSet, payloadStdin bool) string {
	if payloadStdin {
		return "payload"
	}
	for _, name := range []string{tlsconfig.CAFlagName, tlsconfig.CertFlagName, tlsconfig.KeyFlagName} {
		if flag := flags.Lookup(name); flag != nil && flag.Value.String() == "-" {
			return "--" + name
		}
	}
	return ""
}

// HiddenForCompletion lists credential flags that cannot apply to the parsed flags and raw --header values.
func HiddenForCompletion(flags *pflag.FlagSet, headers []string) []string {
	var hidden []string
	if slices.ContainsFunc(headers, isAuthorizationHeader) {
		hidden = append(hidden, sourceFlagNames...)
	}
	if _, ok := Selected(flags); !ok {
		hidden = append(hidden, CleartextFlagName)
	}
	return hidden
}

func isAuthorizationHeader(value string) bool {
	name, _, ok := strings.Cut(value, ":")
	return ok && strings.EqualFold(strings.TrimSpace(name), "Authorization")
}

// RejectHeader keeps a user-supplied Authorization header from competing with a credential flag.
func RejectHeader(flags *pflag.FlagSet, present bool, invalid error) error {
	if source, ok := Selected(flags); ok && present {
		return fmt.Errorf("%w: --%s cannot be combined with an Authorization --header", invalid, source)
	}
	return nil
}

// Value reads the selected credential and returns its Authorization field value.
// Errors name flags, variables, and paths but never credential content.
func Value(
	ctx context.Context, stdin io.Reader, flags *pflag.FlagSet,
	lookupEnv func(string) (string, bool), invalid error,
) (string, bool, error) {
	source, ok := Selected(flags)
	if !ok {
		return "", false, nil
	}
	selection := flags.Lookup(source).Value.String()
	secret := selection
	switch {
	case isFileSource(source):
		data, err := artifact.ReadEncodedSource(ctx, stdin, selection, func(r io.Reader) io.Reader { return r }, MaxBytes)
		if err != nil {
			return "", false, fmt.Errorf("read --%s %q: %w", source, selection, err)
		}
		secret = trimLineEnding(string(data))
		clear(data)
	case isEnvSource(source):
		var set bool
		if secret, set = lookupEnv(selection); !set {
			return "", false, fmt.Errorf("%w: --%s variable %q is not set", invalid, source, selection)
		}
	}
	if len(secret) > MaxBytes {
		return "", false, fmt.Errorf("%w: --%s exceeds %d bytes", invalid, source, MaxBytes)
	}
	if strings.HasPrefix(source, BearerFlagName) {
		value, err := bearer(source, secret, invalid)
		return value, err == nil, err
	}
	value, err := basic(source, secret, invalid)
	return value, err == nil, err
}

func bearer(source, token string, invalid error) (string, error) {
	if token == "" {
		return "", fmt.Errorf("%w: --%s is empty", invalid, source)
	}
	if len(token) > len("Bearer ") && strings.EqualFold(token[:len("Bearer ")], "Bearer ") {
		return "", fmt.Errorf("%w: --%s takes the token alone; the Bearer scheme is added", invalid, source)
	}
	for i := range len(token) {
		if token[i] <= ' ' || token[i] > '~' {
			return "", fmt.Errorf("%w: --%s must be printable ASCII without whitespace", invalid, source)
		}
	}
	return "Bearer " + token, nil
}

func basic(source, credentials string, invalid error) (string, error) {
	user, password, found := strings.Cut(credentials, ":")
	switch {
	case !found:
		return "", fmt.Errorf("%w: --%s requires USER:PASSWORD", invalid, source)
	case user == "":
		return "", fmt.Errorf("%w: --%s requires a user name", invalid, source)
	case !utf8.ValidString(credentials) || strings.ContainsFunc(user+password, isControl):
		return "", fmt.Errorf("%w: --%s must be UTF-8 without control characters", invalid, source)
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials)), nil
}

// isControl matches the ASCII control characters RFC 7617 excludes from credentials:
// C0 controls below space and DEL (0x7f).
func isControl(char rune) bool {
	return char < ' ' || char == 0x7f
}

// trimLineEnding removes the single line ending that editors and echo append.
func trimLineEnding(value string) string {
	if trimmed, found := strings.CutSuffix(value, "\n"); found {
		return strings.TrimSuffix(trimmed, "\r")
	}
	return value
}

func isFileSource(name string) bool {
	return name == BearerFileFlagName || name == BasicFileFlagName
}

func isEnvSource(name string) bool {
	return name == BearerEnvFlagName || name == BasicEnvFlagName
}

func boolFlag(flags *pflag.FlagSet, name string) bool {
	flag := flags.Lookup(name)
	return flag != nil && flag.Value.String() == "true"
}
