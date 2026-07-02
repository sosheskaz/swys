package asym

import (
	"fmt"
	"io"
	"strings"
)

// TextFormatter formats certificate info as human-readable text.
type TextFormatter struct {
	Long bool
}

// Format writes one certificate's information.
func (f *TextFormatter) Format(info *CertInfo, writer io.Writer) error {
	if f.Long {
		return f.formatLong(info, writer)
	}
	return f.formatCompact(info, writer)
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

func (f *TextFormatter) formatCompact(info *CertInfo, writer io.Writer) error {
	if err := writeSummary(info, writer); err != nil {
		return err
	}

	const maxDNSNames = 3
	switch {
	case len(info.DNSNames) > maxDNSNames:
		shown := strings.Join(info.DNSNames[:maxDNSNames], ", ")
		if _, err := fmt.Fprintf(writer, "  DNS: %s, and %d more\n", shown, len(info.DNSNames)-maxDNSNames); err != nil {
			return fmt.Errorf("write DNS names: %w", err)
		}
	case len(info.DNSNames) > 0:
		if _, err := fmt.Fprintf(writer, "  DNS: %s\n", strings.Join(info.DNSNames, ", ")); err != nil {
			return fmt.Errorf("write DNS names: %w", err)
		}
	default:
		if _, err := fmt.Fprintln(writer, "  DNS: (none)"); err != nil {
			return fmt.Errorf("write DNS names: %w", err)
		}
	}
	return nil
}

func (f *TextFormatter) formatLong(info *CertInfo, writer io.Writer) error {
	if err := writeSummary(info, writer); err != nil {
		return err
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
	fields = append(fields, struct{ label, value string }{label: "SHA256", value: info.SHA256Fingerprint})

	for _, field := range fields {
		if err := writeField(writer, field.label, field.value); err != nil {
			return err
		}
	}
	if len(info.Chains) == 0 {
		return nil
	}

	const labelWidth = 12
	if _, err := fmt.Fprintf(writer, "  %*s:\n", labelWidth, "Chains"); err != nil {
		return fmt.Errorf("write certificate chains heading: %w", err)
	}
	for i, chain := range info.Chains {
		chainNames := make([]string, len(chain))
		for j, cert := range chain {
			chainNames[j] = cert.CommonName
			if chainNames[j] == "" {
				chainNames[j] = cert.Subject
			}
		}
		if _, err := fmt.Fprintf(writer, "    [%d] %s\n", i+1, strings.Join(chainNames, " -> ")); err != nil {
			return fmt.Errorf("write certificate chain: %w", err)
		}
	}
	return nil
}

// RequiresChain reports whether text output needs peer chain certificates.
func (f *TextFormatter) RequiresChain() bool {
	return false
}

func writeSummary(info *CertInfo, writer io.Writer) error {
	status := "+"
	if !info.Verified {
		status = "x"
	}
	if _, err := fmt.Fprintf(
		writer,
		"%s %s | %s | expires %s (%s)\n",
		status,
		info.CommonName(),
		info.IssuerCommonName(),
		info.NotAfter.Format("2006-01-02"),
		info.RemainingTime,
	); err != nil {
		return fmt.Errorf("write certificate summary: %w", err)
	}
	if !info.Verified && info.VerifyError != "" {
		if _, err := fmt.Fprintf(writer, "  Error: %s\n", info.VerifyError); err != nil {
			return fmt.Errorf("write certificate verification error: %w", err)
		}
	}
	return nil
}

func writeField(writer io.Writer, label, value string) error {
	const labelWidth = 12
	if _, err := fmt.Fprintf(writer, "  %*s: %s\n", labelWidth, label, value); err != nil {
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
