package asym

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

// TextFormatter formats certificate info as human-readable text.
type TextFormatter struct {
	metadataOnly bool
}

// FormatMultiple writes information for multiple certificates.
func (f *TextFormatter) FormatMultiple(infos []*CertInfo, writer io.Writer) error {
	for i, info := range infos {
		if i > 0 {
			if _, err := fmt.Fprintln(writer); err != nil {
				return fmt.Errorf("separate certificate output: %w", err)
			}
		}
		if err := f.Format(info, writer); err != nil {
			return err
		}
	}
	return nil
}

// Format writes one certificate's information.
func (f *TextFormatter) Format(info *CertInfo, writer io.Writer) error {
	if err := writeSummary(info, writer, f.metadataOnly); err != nil {
		return err
	}
	publicKeyFingerprint := "(unavailable)"
	if fingerprint, err := info.PublicKeySHA256Fingerprint(); err == nil {
		publicKeyFingerprint = fingerprint
	}

	fields := []struct {
		label string
		value string
	}{
		{label: "Subject", value: info.Subject},
		{label: "Issuer", value: info.Issuer},
		{label: "Serial", value: info.SerialNumber},
		{label: "DNS Names", value: joinOrNone(info.DNSNames)},
		{label: "IPs", value: joinOrNone(info.IPAddresses)},
		{label: "Not Before", value: info.NotBefore.Local().Format("2006-01-02 15:04:05 MST")},
		{label: "Not After", value: info.NotAfter.Local().Format("2006-01-02 15:04:05 MST")},
		{label: "Key", value: fmt.Sprintf("%s, %s", info.PublicKeyAlgorithm, info.SignatureAlgorithm)},
	}
	if len(info.KeyUsage) > 0 {
		fields = append(fields, struct{ label, value string }{label: "Usage", value: strings.Join(info.KeyUsage, ", ")})
	}
	if len(info.ExtKeyUsage) > 0 {
		fields = append(fields, struct{ label, value string }{label: "Ext Usage", value: strings.Join(info.ExtKeyUsage, ", ")})
	}
	if info.IsCA {
		fields = append(fields, struct{ label, value string }{label: "CA", value: "true"})
	}
	fields = append(
		fields,
		struct{ label, value string }{label: "SHA256", value: info.SHA256Fingerprint},
		struct{ label, value string }{label: "Public Key SHA256", value: publicKeyFingerprint},
	)

	for _, field := range fields {
		if err := writeField(writer, field.label, field.value); err != nil {
			return err
		}
	}
	return writeCertificateChains(writer, info.Chains)
}

func writeCertificateChains(writer io.Writer, chains [][]ChainCertInfo) error {
	if len(chains) == 0 {
		return nil
	}
	const labelWidth = 12
	if _, err := fmt.Fprintf(writer, "  %*s:\n", labelWidth, "Chains"); err != nil {
		return fmt.Errorf("write certificate chains heading: %w", err)
	}
	for i, chain := range chains {
		chainNames := make([]string, len(chain))
		for j, cert := range chain {
			chainNames[j] = cert.CommonName
			if chainNames[j] == "" {
				chainNames[j] = cert.Subject
			}
		}
		if _, err := fmt.Fprintf(writer, "    [%d] %s\n", i+1, EscapeDiagnosticValue(strings.Join(chainNames, " -> "))); err != nil {
			return fmt.Errorf("write certificate chain: %w", err)
		}
	}
	return nil
}

// FormatReport renders selection details and reports verification of the original leaf.
func (f *TextFormatter) FormatReport(report *CertificateReport, w io.Writer) error {
	metadata := &TextFormatter{metadataOnly: true}
	if err := metadata.FormatMultiple(report.Certificates, w); err != nil {
		return err
	}
	if err := report.Verification.WriteText(w); err != nil {
		return err
	}
	return writeCertificateChains(w, report.Verification.chainNames)
}

// WriteText writes terminal-safe verification diagnostics.
func (v CertificateVerification) WriteText(w io.Writer) error {
	status := "not verified"
	if v.Verified {
		status = "verified"
	} else if v.Error != "" {
		status += ": " + EscapeDiagnosticValue(v.Error)
	}
	if _, err := fmt.Fprintf(w, "certificate verification: %s\n", status); err != nil {
		return fmt.Errorf("write certificate verification status: %w", err)
	}
	return nil
}

func writeSummary(info *CertInfo, writer io.Writer, metadataOnly bool) error {
	status := "+ "
	if !info.Verified {
		status = "x "
	}
	if metadataOnly {
		status = ""
	}
	if _, err := fmt.Fprintf(
		writer,
		"%s%s | %s | expires %s (%s)\n",
		status,
		EscapeDiagnosticValue(info.CommonName()),
		EscapeDiagnosticValue(info.IssuerCommonName()),
		info.NotAfter.Format("2006-01-02"),
		EscapeDiagnosticValue(info.RemainingTime),
	); err != nil {
		return fmt.Errorf("write certificate summary: %w", err)
	}
	if !metadataOnly && !info.Verified && info.VerifyError != "" {
		if _, err := fmt.Fprintf(writer, "  Error: %s\n", EscapeDiagnosticValue(info.VerifyError)); err != nil {
			return fmt.Errorf("write certificate verification error: %w", err)
		}
	}
	return nil
}

func writeField(writer io.Writer, label, value string) error {
	const labelWidth = 12
	if _, err := fmt.Fprintf(writer, "  %*s: %s\n", labelWidth, label, EscapeDiagnosticValue(value)); err != nil {
		return fmt.Errorf("write certificate field %q: %w", label, err)
	}
	return nil
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}

// EscapeDiagnosticValue keeps untrusted values on one terminal-safe display line.
func EscapeDiagnosticValue(value string) string {
	var escaped strings.Builder
	for _, char := range value {
		if strconv.IsPrint(char) {
			escaped.WriteRune(char)
		} else {
			quoted := strconv.QuoteRune(char)
			escaped.WriteString(quoted[1 : len(quoted)-1])
		}
	}
	return escaped.String()
}
