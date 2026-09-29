package cert

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/encoding"
	"github.com/sosheskaz-systems/npc/internal/asym"
)

const (
	formatJSON = "json"
	formatText = "text"
)

var certFormatters = map[string]func() asym.CertFormatter{
	"text":     func() asym.CertFormatter { return &asym.TextFormatter{} },
	"long":     func() asym.CertFormatter { return &asym.TextFormatter{Long: true} },
	formatJSON: func() asym.CertFormatter { return &asym.JSONFormatter{Indent: true} },
	"pem":      func() asym.CertFormatter { return &asym.PEMFormatter{} },
}

// ErrFormatSelectsStructuredOutput identifies a byte encoding supplied as a certificate output format.
var ErrFormatSelectsStructuredOutput = errors.New("--format selects structured output, not byte encoding")

func getCertFormatter(format string) (asym.CertFormatter, error) {
	constructor, ok := certFormatters[format]
	if !ok {
		if encoding.Has(format) {
			return nil, fmt.Errorf("unknown output format %q (valid: %s): %w", format, strings.Join(certFormatNames(), ", "), ErrFormatSelectsStructuredOutput)
		}
		return nil, fmt.Errorf("%w %q (valid: %s)", errUnknownCertFormat, format, strings.Join(certFormatNames(), ", "))
	}
	return constructor(), nil
}

func certFormatNames() []string {
	return slices.Sorted(maps.Keys(certFormatters))
}

func certFormatterFromCommand(cmd *cobra.Command) (asym.CertFormatter, error) {
	format, err := cmd.Flags().GetString(commandio.FormatFlagName)
	if err != nil {
		return nil, fmt.Errorf("read format flag: %w", err)
	}
	return getCertFormatter(format)
}

type inspectionResultKey struct{}

func prepareInspection(cmd *cobra.Command, certs []*x509.Certificate, options *x509.VerifyOptions, source string) ([]byte, error) {
	formatter, err := certFormatterFromCommand(cmd)
	if err != nil {
		return nil, err
	}
	selection, err := cmd.Flags().GetString("select")
	if err != nil {
		return nil, fmt.Errorf("read selection flag: %w", err)
	}
	report, err := asym.InspectCertificates(certs, options, selection, source)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := formatter.FormatReport(report, &output); err != nil {
		return nil, err
	}
	if _, pemOutput := formatter.(*asym.PEMFormatter); pemOutput {
		cmd.SetContext(context.WithValue(cmd.Context(), inspectionResultKey{}, report.Verification))
	}
	return output.Bytes(), nil
}

func runPreparedInspection(cmd *cobra.Command, _ []string) error {
	prepared, output, err := commandio.TakePrepared(cmd)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, bytes.NewReader(prepared)); err != nil {
		return fmt.Errorf("write certificate output: %w", err)
	}
	if verification, ok := cmd.Context().Value(inspectionResultKey{}).(asym.CertificateVerification); ok {
		return verification.WriteText(cmd.ErrOrStderr())
	}
	return nil
}

func addCertificateSelection(cmd *cobra.Command, defaultSelection string) {
	cmd.Flags().String("select", defaultSelection, "certificates to export (leaf, chain, fullchain, root, or index: 0=root, last=leaf)")
	commandio.RegisterDescribedFlagCompletion(cmd, "select", func() []string {
		return []string{asym.SelectLeaf, asym.SelectChain, asym.SelectFullChain, asym.SelectRoot, "0", "1"}
	}, map[string]string{
		asym.SelectLeaf:      "first certificate",
		asym.SelectChain:     "supplied certificates after the leaf",
		asym.SelectFullChain: "all supplied certificates",
		asym.SelectRoot:      "verified trust anchors or a supplied self-signed CA",
		"0":                  "root of an unambiguous complete chain",
		"1":                  "next certificate toward the leaf, if present",
	})
}

func validateInspectionFlags(cmd *cobra.Command) error {
	if _, err := certFormatterFromCommand(cmd); err != nil {
		return err
	}
	selection, err := cmd.Flags().GetString("select")
	if err != nil {
		return fmt.Errorf("read selection flag: %w", err)
	}
	return asym.ValidateCertificateSelection(selection)
}
