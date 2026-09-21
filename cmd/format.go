package cmd

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/asym"
)

const (
	formatJSON = "json"
	formatText = "text"
)

var certFormatters = map[string]func() asym.CertFormatter{
	"text":      func() asym.CertFormatter { return &asym.TextFormatter{} },
	"long":      func() asym.CertFormatter { return &asym.TextFormatter{Long: true} },
	formatJSON:  func() asym.CertFormatter { return &asym.JSONFormatter{Indent: true} },
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

func formatCertificates(
	cmd *cobra.Command,
	formatter asym.CertFormatter,
	infos []*asym.CertInfo,
) error {
	output := cmd.OutOrStdout()
	var err error
	if len(infos) == 1 {
		err = formatter.Format(infos[0], output)
	} else {
		err = formatter.FormatMultiple(infos, output)
	}
	if err != nil {
		return err
	}
	if certificateFormatterIncludesVerification(formatter) {
		return nil
	}
	return writeCertificateVerificationStatus(cmd.ErrOrStderr(), infos)
}

func certificateFormatterIncludesVerification(formatter asym.CertFormatter) bool {
	switch formatter.(type) {
	case *asym.JSONFormatter, *asym.TextFormatter:
		return true
	default:
		return false
	}
}

func writeCertificateVerificationStatus(output io.Writer, infos []*asym.CertInfo) error {
	for i, info := range infos {
		label := "certificate verification"
		if len(infos) > 1 {
			label = fmt.Sprintf("certificate %d verification", i+1)
		}
		status := "not verified"
		if info.Verified {
			status = "verified"
		} else if info.VerifyError != "" {
			status += ": " + asym.EscapeDiagnosticValue(info.VerifyError)
		}
		if _, err := fmt.Fprintf(output, "%s: %s\n", label, status); err != nil {
			return fmt.Errorf("write certificate verification status: %w", err)
		}
	}
	return nil
}
