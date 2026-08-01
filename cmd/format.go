package cmd

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/asym"
)

var certFormatters = map[string]func() asym.CertFormatter{
	"text":      func() asym.CertFormatter { return &asym.TextFormatter{} },
	"long":      func() asym.CertFormatter { return &asym.TextFormatter{Long: true} },
	"json":      func() asym.CertFormatter { return &asym.JSONFormatter{Indent: true} },
	"pem":       func() asym.CertFormatter { return &asym.PEMFormatter{} },
	"chain":     func() asym.CertFormatter { return &asym.ChainPEMFormatter{} },
	"fullchain": func() asym.CertFormatter { return &asym.PEMFormatter{FullChain: true} },
}

var errFormatSelectsStructuredOutput = errors.New("--format selects structured output, not byte encoding")

func getCertFormatter(format string) (asym.CertFormatter, error) {
	constructor, ok := certFormatters[format]
	if !ok {
		if _, isEncoding := byteEncodings[format]; isEncoding {
			return nil, fmt.Errorf("unknown output format %q (valid: %s): %w", format, strings.Join(certFormatNames(), ", "), errFormatSelectsStructuredOutput)
		}
		return nil, fmt.Errorf("%w %q (valid: %s)", errUnknownCertFormat, format, strings.Join(certFormatNames(), ", "))
	}
	return constructor(), nil
}

func certFormatNames() []string {
	return sortedKeys(certFormatters)
}

func certFormatterFromCommand(cmd *cobra.Command) (asym.CertFormatter, error) {
	format, err := cmd.Flags().GetString(formatFlagName)
	if err != nil {
		return nil, fmt.Errorf("read format flag: %w", err)
	}
	return getCertFormatter(format)
}

func formatCertificates(formatter asym.CertFormatter, infos []*asym.CertInfo, output io.Writer) error {
	if len(infos) == 1 {
		return formatter.Format(infos[0], output)
	}
	return formatter.FormatMultiple(infos, output)
}
