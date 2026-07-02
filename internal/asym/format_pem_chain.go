package asym

import (
	"encoding/pem"
	"io"
)

// ChainPEMFormatter outputs only the chain certificates (excluding the leaf) as PEM
// Useful for extracting intermediate/root certificates.
type ChainPEMFormatter struct{}

// Format writes nothing for a single certificate (no chain available).
func (f *ChainPEMFormatter) Format(info *CertInfo, w io.Writer) error {
	// For a single cert, there's no chain to output
	return nil
}

// FormatMultiple writes certificates 2+ as PEM blocks (skips the first/leaf cert).
func (f *ChainPEMFormatter) FormatMultiple(infos []*CertInfo, w io.Writer) error {
	if len(infos) <= 1 {
		// No chain certificates to output
		return nil
	}

	// Skip the first cert (leaf), output the rest (chain)
	for _, info := range infos[1:] {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: info.RawDER,
		}
		if err := pem.Encode(w, block); err != nil {
			return err
		}
	}
	return nil
}

// FullChainPEMFormatter outputs all certificates (leaf + chain) as PEM
// Useful for saving complete certificate chains.
type FullChainPEMFormatter struct{}

// Format writes a single certificate as PEM (same as PEMFormatter).
func (f *FullChainPEMFormatter) Format(info *CertInfo, w io.Writer) error {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: info.RawDER,
	}
	return pem.Encode(w, block)
}

// FormatMultiple writes all certificates as PEM blocks.
func (f *FullChainPEMFormatter) FormatMultiple(infos []*CertInfo, w io.Writer) error {
	for _, info := range infos {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: info.RawDER,
		}
		if err := pem.Encode(w, block); err != nil {
			return err
		}
	}
	return nil
}
