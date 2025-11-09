package sym

type BitSize uint16

const (
	DefaultAESBitSize BitSize = 128
)

type AES struct {
	Bits BitSize
}
