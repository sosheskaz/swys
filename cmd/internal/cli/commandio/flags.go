// Package commandio provides shared command flags, stream setup, and cleanup.
package commandio

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/encoding"
)

// EncodingFlagName and its peers name shared encoding and format flags.
const (
	EncodingFlagName      = "encoding"
	InputEncodingFlagName = "input-encoding"
	FormatFlagName        = "format"
)

// ByteEncodingDescriptions supplies help and completion text for byte encodings.
var ByteEncodingDescriptions = map[string]string{
	encoding.Raw: "unencoded bytes",
	encoding.Hex: "hexadecimal",
	"base64":     "standard Base64 with padding",
	"b64":        "alias for base64",
	"base64url":  "URL-safe Base64 (unpadded output)",
	"base32":     "standard Base32 with padding",
}

// StructuredFormatDescriptions supplies help and completion text for formats.
var StructuredFormatDescriptions = map[string]string{
	"text":  "human-readable text",
	"plain": "plain text without terminal styles",
	"json":  "structured JSON",
	"pem":   "certificate PEM",
}

// BinaryOutputCommand adds output encoding and optional input decoding flags.
func BinaryOutputCommand(command *cobra.Command, acceptsInput bool) *cobra.Command {
	AddShape(command, "binary-output")
	AddOutputEncodingFlag(command)
	if acceptsInput {
		AddInputEncodingFlag(command)
	}
	return command
}

// AddOutputEncodingFlag adds byte encoding independently of output representation.
func AddOutputEncodingFlag(command *cobra.Command) {
	command.Flags().StringP(EncodingFlagName, "e", encoding.Raw,
		"output encoding ("+strings.Join(encoding.Names(), ", ")+")")
	registerEncodingCompletion(command, EncodingFlagName)
}

// SensitiveBinaryOutputCommand marks encoded output as private by default.
func SensitiveBinaryOutputCommand(command *cobra.Command, acceptsInput bool) *cobra.Command {
	AddShape(command, "sensitive-output")
	return BinaryOutputCommand(command, acceptsInput)
}

// EncodedInputCommand adds the input decoding flag.
func EncodedInputCommand(command *cobra.Command) *cobra.Command {
	AddInputEncodingFlag(command)
	return command
}

// StructuredOutputCommand adds the format flag and its completions.
func StructuredOutputCommand(command *cobra.Command, formats func() []string) *cobra.Command {
	AddShape(command, "structured-output")
	command.Flags().StringP(FormatFlagName, "f", "text", "structured output format ("+strings.Join(formats(), ", ")+")")
	RegisterDescribedFlagCompletion(command, FormatFlagName, formats, StructuredFormatDescriptions)
	return command
}

// AddInputEncodingFlag registers input decoding and completion.
func AddInputEncodingFlag(command *cobra.Command) {
	command.Flags().String(InputEncodingFlagName, encoding.Raw,
		"input encoding ("+strings.Join(encoding.Names(), ", ")+")")
	registerEncodingCompletion(command, InputEncodingFlagName)
}

// AddShape marks a generic presentation capability on command.
func AddShape(command *cobra.Command, shape string) {
	if command.Annotations == nil {
		command.Annotations = make(map[string]string)
	}
	command.Annotations["swys.shape."+shape] = "true"
}

// HasShape reports whether command has a presentation capability.
func HasShape(command *cobra.Command, shape string) bool {
	return command.Annotations["swys.shape."+shape] == "true"
}

// InputDecoderFromCommand selects the decoder named by the input encoding flag.
func InputDecoderFromCommand(command *cobra.Command) (encoding.InputDecoder, error) {
	if command.Flags().Lookup(InputEncodingFlagName) == nil {
		return func(input io.Reader) io.Reader { return input }, nil
	}
	name, err := command.Flags().GetString(InputEncodingFlagName)
	if err != nil {
		return nil, fmt.Errorf("read input-encoding flag: %w", err)
	}
	return encoding.GetInputDecoder(name)
}

// CommandInput selects positional input or the command input stream.
func CommandInput(command *cobra.Command, args []string) (io.Reader, error) {
	if len(args) == 0 || args[0] == "-" {
		return command.InOrStdin(), nil
	}
	input := strings.NewReader(strings.Join(args, " "))
	decoder, err := InputDecoderFromCommand(command)
	if err != nil {
		return nil, err
	}
	return decoder(input), nil
}

func registerEncodingCompletion(command *cobra.Command, flagName string) {
	if err := command.RegisterFlagCompletionFunc(flagName,
		func(command *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
			if flag := command.Flag(flagName); flag != nil && flag.Hidden {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			values := make([]string, 0, len(encoding.Names()))
			for _, name := range encoding.Names() {
				if strings.HasPrefix(name, prefix) {
					values = append(values, cobra.CompletionWithDesc(name, ByteEncodingDescriptions[name]))
				}
			}
			return values, cobra.ShellCompDirectiveNoFileComp
		}); err != nil {
		panic(err)
	}
}

// RegisterFlagCompletion registers candidate values for a flag.
func RegisterFlagCompletion(command *cobra.Command, name string, values func() []string) {
	if err := command.RegisterFlagCompletionFunc(name, func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return values(), cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		panic(err)
	}
}

// RegisterDescribedFlagCompletion adds descriptions to candidate values.
func RegisterDescribedFlagCompletion(command *cobra.Command, name string, values func() []string, descriptions map[string]string) {
	if err := command.RegisterFlagCompletionFunc(name, func(_ *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
		matches := make([]string, 0)
		for _, value := range values() {
			if !strings.HasPrefix(value, prefix) {
				continue
			}
			if description := descriptions[value]; description != "" {
				matches = append(matches, cobra.CompletionWithDesc(value, description))
			} else {
				matches = append(matches, value)
			}
		}
		return matches, cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		panic(err)
	}
}

// CompletionsWithDescriptions pairs candidates with available descriptions.
func CompletionsWithDescriptions(values []string, descriptions map[string]string) []string {
	completions := make([]string, 0, len(values))
	for _, value := range values {
		if description := descriptions[value]; description != "" {
			completions = append(completions, cobra.CompletionWithDesc(value, description))
		} else {
			completions = append(completions, value)
		}
	}
	return completions
}
