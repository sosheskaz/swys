package asym

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/sosheskaz/swys/internal/textdisplay"
)

func certificateTextReport(report *CertificateReport, writer io.Writer, options textdisplay.Options) error {
	printer := textdisplay.New(writer, options)
	printer.Heading("Certificates · " + report.Selection)
	for index, info := range report.Certificates {
		printer.Section(fmt.Sprintf("Certificate %d · %s", index+1, info.CommonName()))
		printer.Fields([]textdisplay.Field{
			{Label: "Subject", Value: info.Subject},
			{Label: "Issuer", Value: info.Issuer},
			{Label: "Serial", Value: info.SerialNumber},
			{Label: "Source", Value: info.Source},
			{Label: "DNS Names", Value: joinOrNone(info.DNSNames)},
			{Label: "IPs", Value: joinOrNone(info.IPAddresses)},
		})
		printer.Section("Validity")
		printer.Fields([]textdisplay.Field{
			{Label: "Not Before", Value: info.NotBefore.Local().Format("2006-01-02 15:04:05 MST")},
			{Label: "Not After", Value: info.NotAfter.Local().Format("2006-01-02 15:04:05 MST")},
			{Label: "Remaining", Value: info.RemainingTime},
		})
		fingerprint := "(unavailable)"
		if value, err := info.PublicKeySHA256Fingerprint(); err == nil {
			fingerprint = value
		}
		printer.Section("Public Key and Usage")
		printer.Fields([]textdisplay.Field{
			{Label: "Key", Value: info.PublicKeyAlgorithm},
			{Label: "Signature", Value: info.SignatureAlgorithm},
			{Label: "Usage", Value: joinOrNone(info.KeyUsage)},
			{Label: "Ext Usage", Value: joinOrNone(info.ExtKeyUsage)},
			{Label: "CA", Value: strconv.FormatBool(info.IsCA)},
			{Label: "SHA256", Value: info.SHA256Fingerprint},
			{Label: publicKeyFingerprintLabel, Value: fingerprint},
		})
	}
	if err := printer.Err(); err != nil {
		return err
	}
	return report.Verification.WriteReport(writer, options)
}

// WriteReport writes the original leaf's verification independently of selection.
func (verification CertificateVerification) WriteReport(writer io.Writer, options textdisplay.Options) error {
	printer := textdisplay.New(writer, options)
	printer.Section("Certificate Verification · original leaf")
	status, role := "not verified", textdisplay.Warning
	if verification.Verified {
		status, role = "verified", textdisplay.Success
	}
	fields := []textdisplay.Field{{Label: "Status", Value: status, Role: role}}
	if verification.Error != "" {
		fields = append(fields, textdisplay.Field{Label: "Error", Value: verification.Error, Role: textdisplay.Failure})
	}
	for index, chain := range verification.chainNames {
		names := make([]string, len(chain))
		for i, cert := range chain {
			names[i] = cert.CommonName
			if names[i] == "" {
				names[i] = cert.Subject
			}
		}
		fields = append(fields, textdisplay.Field{Label: fmt.Sprintf("Chain %d", index+1), Value: strings.Join(names, " -> ")})
	}
	printer.Fields(fields)
	return printer.Err()
}

func keyTextReport(info *KeyInfo, writer io.Writer, options textdisplay.Options) error {
	printer := textdisplay.New(writer, options)
	printer.Heading("Key Metadata")
	fields := []textdisplay.Field{
		{Label: "Key Type", Value: string(info.KeyType)},
		{Label: "Algorithm", Value: info.Algorithm},
		{Label: "Bits", Value: strconv.Itoa(info.Bits)},
	}
	if info.Curve != "" {
		fields = append(fields, textdisplay.Field{Label: "Curve", Value: info.Curve})
	}
	fields = append(fields, textdisplay.Field{Label: publicKeyFingerprintLabel, Value: info.PublicKeySHA256Fingerprint})
	printer.Fields(fields)
	return printer.Err()
}
