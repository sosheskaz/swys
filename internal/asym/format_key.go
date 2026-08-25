package asym

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
)

// KeyFormatter renders safe key metadata.
type KeyFormatter interface {
	Format(info *KeyInfo, writer io.Writer) error
}

// KeyTextFormatter renders key metadata as human-readable text.
type KeyTextFormatter struct{}

// Format writes key metadata as text.
func (f *KeyTextFormatter) Format(info *KeyInfo, writer io.Writer) error {
	if err := writeKeyField(writer, "Key Type", string(info.KeyType)); err != nil {
		return err
	}
	if err := writeKeyField(writer, "Algorithm", info.Algorithm); err != nil {
		return err
	}
	if err := writeKeyField(writer, "Bits", strconv.Itoa(info.Bits)); err != nil {
		return err
	}
	if info.Curve != "" {
		if err := writeKeyField(writer, "Curve", info.Curve); err != nil {
			return err
		}
	}
	return writeKeyField(writer, "Public Key SHA256", info.PublicKeySHA256Fingerprint)
}

func writeKeyField(writer io.Writer, label, value string) error {
	if _, err := fmt.Fprintf(writer, "%s: %s\n", label, value); err != nil {
		return fmt.Errorf("write key field %q: %w", label, err)
	}
	return nil
}

// KeyJSONFormatter renders key metadata as JSON.
type KeyJSONFormatter struct {
	Indent bool
}

// Format writes key metadata as JSON.
func (f *KeyJSONFormatter) Format(info *KeyInfo, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	if f.Indent {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(info); err != nil {
		return fmt.Errorf("encode key JSON: %w", err)
	}
	return nil
}
