package asym

import (
	"encoding/pem"
	"fmt"
	"io"
)

// ChainPEMFormatter outputs only the chain certificates (excluding the leaf) as PEM
// Useful for extracting intermediate/root certificates.
type ChainPEMFormatter struct{}

// RequiresChain reports that chain output needs peer chain certificates.
func (f *ChainPEMFormatter) RequiresChain() bool {
	return true
}

// Format writes nothing for a single certificate (no chain available).
func (f *ChainPEMFormatter) Format(_ *CertInfo, _ io.Writer) error {
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
			Type:  certificatePEMType,
			Bytes: info.RawDER,
		}
		if err := pem.Encode(w, block); err != nil {
			return fmt.Errorf("encode chain certificate PEM: %w", err)
		}
	}
	return nil
}
