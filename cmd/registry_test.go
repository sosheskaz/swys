package cmd

import (
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestByteEncodingRegistryDrivesHelpErrorsAndCompletion(t *testing.T) { //nolint:paralleltest // mutates a package-level formatter or encoding registry
	// byteEncodings is package-global; do not make this test parallel.
	byteEncodings["fake"] = byteEncoding{
		encoder: func(output io.Writer) (io.Writer, io.Closer) { return output, nil },
		decoder: func(input io.Reader) io.Reader { return input },
	}
	t.Cleanup(func() { delete(byteEncodings, "fake") })

	command := binaryOutputCommand(&cobra.Command{Use: "registry-test"}, true)
	for _, flagName := range []string{encodingFlagName, inputEncodingFlagName} {
		flag := command.Flags().Lookup(flagName)
		if flag == nil {
			t.Fatalf("%s flag not registered", flagName)
		}
		if !strings.Contains(flag.Usage, "fake") {
			t.Fatalf("%s usage = %q, want fake registry value", flagName, flag.Usage)
		}
		completion, ok := command.GetFlagCompletionFunc(flagName)
		if !ok {
			t.Fatalf("%s has no completion function", flagName)
		}
		values, directive := completion(command, nil, "")
		if !slices.Contains(values, "fake") {
			t.Fatalf("%s completions = %v, want fake", flagName, values)
		}
		if directive != cobra.ShellCompDirectiveNoFileComp {
			t.Fatalf("%s directive = %v, want no-file completion", flagName, directive)
		}
	}

	if _, err := getOutputEncoder("missing"); err == nil || !strings.Contains(err.Error(), "fake") {
		t.Fatalf("output error = %v, want fake registry value", err)
	}
	if _, err := getInputDecoder("missing"); err == nil || !strings.Contains(err.Error(), "fake") {
		t.Fatalf("input error = %v, want fake registry value", err)
	}
}

func TestFormatterRegistryDrivesHelpErrorsAndCompletion(t *testing.T) { //nolint:paralleltest // mutates a package-level formatter or encoding registry
	// certFormatters is package-global; do not make this test parallel.
	certFormatters["fake"] = certFormatters["text"]
	t.Cleanup(func() { delete(certFormatters, "fake") })

	command := structuredOutputCommand(&cobra.Command{Use: "registry-test"}, certFormatNames)
	flag := command.Flags().Lookup(formatFlagName)
	if flag == nil {
		t.Fatal("format flag not registered")
	}
	if !strings.Contains(flag.Usage, "fake") {
		t.Fatalf("format usage = %q, want fake registry value", flag.Usage)
	}
	completion, ok := command.GetFlagCompletionFunc(formatFlagName)
	if !ok {
		t.Fatal("format has no completion function")
	}
	values, _ := completion(command, nil, "")
	if !slices.Contains(values, "fake") {
		t.Fatalf("format completions = %v, want fake", values)
	}
	if _, err := getCertFormatter("missing"); err == nil || !strings.Contains(err.Error(), "fake") {
		t.Fatalf("format error = %v, want fake registry value", err)
	}
}
