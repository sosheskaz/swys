package asym

import (
	"fmt"
	"io"
	"strings"
)

// TextFormatter formats certificate info as human-readable text.
type TextFormatter struct {
	Long bool // If true, show detailed output; if false, show compact summary
}

// Format writes a single certificate's info to the writer.
func (f *TextFormatter) Format(info *CertInfo, w io.Writer) error {
	if f.Long {
		return f.formatLong(info, w)
	}
	return f.formatCompact(info, w)
}

// FormatMultiple writes multiple certificates' info to the writer.
func (f *TextFormatter) FormatMultiple(infos []*CertInfo, w io.Writer) error {
	for i, info := range infos {
		if i > 0 {
			fmt.Fprintln(w)
		}
		if err := f.Format(info, w); err != nil {
			return err
		}
	}
	return nil
}

// formatCompact produces a minimal summary output.
func (f *TextFormatter) formatCompact(info *CertInfo, w io.Writer) error {
	// Status indicator and summary line
	status := "+"
	if !info.Verified {
		status = "x"
	}

	// Format expiry info
	expiryStr := info.NotAfter.Format("2006-01-02")
	remainingStr := info.RemainingTime

	fmt.Fprintf(w, "%s %s | %s | expires %s (%s)\n",
		status,
		info.CommonName(),
		info.IssuerCommonName(),
		expiryStr,
		remainingStr,
	)

	// Show verification error if present
	if !info.Verified && info.VerifyError != "" {
		fmt.Fprintf(w, "  Error: %s\n", info.VerifyError)
	}

	// DNS names (truncate if too many)
	const maxDNSNames = 3
	if len(info.DNSNames) > maxDNSNames {
		shown := strings.Join(info.DNSNames[:maxDNSNames], ", ")
		fmt.Fprintf(w, "  DNS: %s, and %d more\n", shown, len(info.DNSNames)-maxDNSNames)
	} else if len(info.DNSNames) > 0 {
		fmt.Fprintf(w, "  DNS: %s\n", strings.Join(info.DNSNames, ", "))
	} else {
		fmt.Fprintln(w, "  DNS: (none)")
	}

	return nil
}

// formatLong produces detailed output with all certificate fields.
func (f *TextFormatter) formatLong(info *CertInfo, w io.Writer) error {
	// Status indicator and summary line (same as compact)
	status := "+"
	if !info.Verified {
		status = "x"
	}

	expiryStr := info.NotAfter.Format("2006-01-02")
	remainingStr := info.RemainingTime

	fmt.Fprintf(w, "%s %s | %s | expires %s (%s)\n",
		status,
		info.CommonName(),
		info.IssuerCommonName(),
		expiryStr,
		remainingStr,
	)

	// Show verification error if present
	if !info.Verified && info.VerifyError != "" {
		fmt.Fprintf(w, "  Error: %s\n", info.VerifyError)
	}

	// Detailed fields with aligned labels
	const labelWidth = 12

	printField := func(label, value string) {
		fmt.Fprintf(w, "  %*s: %s\n", labelWidth, label, value)
	}

	printField("Subject", info.Subject)
	printField("Issuer", info.Issuer)
	printField("Serial", info.SerialNumber)

	// DNS Names
	if len(info.DNSNames) > 0 {
		printField("DNS Names", strings.Join(info.DNSNames, ", "))
	} else {
		printField("DNS Names", "(none)")
	}

	// IP Addresses
	if len(info.IPAddresses) > 0 {
		printField("IPs", strings.Join(info.IPAddresses, ", "))
	} else {
		printField("IPs", "(none)")
	}

	// Validity period
	printField("Not Before", info.NotBefore.Local().Format("2006-01-02 15:04:05 MST"))
	printField("Not After", info.NotAfter.Local().Format("2006-01-02 15:04:05 MST"))

	// Key info
	printField("Key", fmt.Sprintf("%s, %s", info.PublicKeyAlgorithm, info.SignatureAlgorithm))

	// Key usage
	if len(info.KeyUsage) > 0 {
		printField("Usage", strings.Join(info.KeyUsage, ", "))
	}

	// Extended key usage
	if len(info.ExtKeyUsage) > 0 {
		printField("Ext Usage", strings.Join(info.ExtKeyUsage, ", "))
	}

	// CA flag
	if info.IsCA {
		printField("CA", "true")
	}

	// SHA256 fingerprint
	printField("SHA256", info.SHA256Fingerprint)

	// Chains
	if len(info.Chains) > 0 {
		fmt.Fprintf(w, "  %*s:\n", labelWidth, "Chains")
		for i, chain := range info.Chains {
			chainStrs := make([]string, len(chain))
			for j, c := range chain {
				// Extract just the CN for brevity
				chainStrs[j] = extractCN(c.Subject)
			}
			fmt.Fprintf(w, "    [%d] %s\n", i+1, strings.Join(chainStrs, " -> "))
		}
	}

	return nil
}
