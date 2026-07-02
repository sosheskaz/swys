package sym

// BitSize is a cryptographic key size in bits.
type BitSize uint16

const (
	// DefaultAESBitSize is the default AES key size.
	DefaultAESBitSize BitSize = 128
)

// AES configures an AES operation.
type AES struct {
	Bits BitSize
}
