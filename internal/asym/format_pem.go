package asym

import (
	"encoding/pem"
	"fmt"
	"io"
)

const certificatePEMType = "CERTIFICATE"

// PEMFormatter outputs the raw PEM certificate only.
type PEMFormatter struct {
	FullChain bool
}

// RequiresChain reports whether this formatter emits the full certificate chain.
func (f *PEMFormatter) RequiresChain() bool {
	return f.FullChain
}

// Format writes a single certificate as PEM.
func (f *PEMFormatter) Format(info *CertInfo, w io.Writer) error {
	block := &pem.Block{
		Type:  certificatePEMType,
		Bytes: info.RawDER,
	}
	if err := pem.Encode(w, block); err != nil {
		return fmt.Errorf("encode certificate PEM: %w", err)
	}
	return nil
}

// FormatMultiple writes multiple certificates as PEM blocks.
func (f *PEMFormatter) FormatMultiple(infos []*CertInfo, w io.Writer) error {
	for _, info := range infos {
		if err := f.Format(info, w); err != nil {
			return err
		}
	}
	return nil
}
