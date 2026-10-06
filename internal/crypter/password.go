package crypter

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/bits"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
)

// Password KDF limits apply to encryption and to every wrapper before decryption
// derives a key; there is no override.
const (
	MaxPasswordKDFMemoryKiB = 256 << 10
	MaxPasswordKDFPasses    = 10
	MaxPasswordKDFLanes     = 16
	// maxPasswordKDFWork is the cumulative memory-passes allowed across wrappers.
	maxPasswordKDFWork  = MaxPasswordKDFMemoryKiB * MaxPasswordKDFPasses
	maxPasswordWrappers = 16
	// argon2S2KLength is the S2K specifier size: mode, salt, passes, lanes, memory.
	argon2S2KLength = 1 + s2k.Argon2SaltSize + 3
)

var (
	// ErrInvalidArgon2Parameters reports a KDF cost that OpenPGP cannot represent exactly.
	ErrInvalidArgon2Parameters = errors.New("invalid Argon2 parameters")
	// ErrPasswordKDFLimit reports a KDF cost above SwYS's unconditional limits.
	ErrPasswordKDFLimit = errors.New("OpenPGP password KDF exceeds limit")
	// ErrOpenPGPPassword reports a password that unlocks none of the message's wrappers.
	ErrOpenPGPPassword = errors.New("OpenPGP password does not match")
	errPasswordWrapper = errors.New("invalid OpenPGP password wrapper")
)

// Argon2Parameters specifies Argon2id memory in KiB, passes, and lanes.
type Argon2Parameters struct {
	MemoryKiB   uint32
	Passes      uint32
	Parallelism uint32
}

// DefaultArgon2Parameters returns the 64 MiB, three-pass, four-lane profile.
func DefaultArgon2Parameters() Argon2Parameters {
	return Argon2Parameters{MemoryKiB: 64 << 10, Passes: 3, Parallelism: 4}
}

// Validate rejects costs OpenPGP would round and costs above SwYS's limits.
func (p Argon2Parameters) Validate() error {
	if err := p.checkLimits(); err != nil {
		return err
	}
	if p.Passes == 0 || p.Parallelism == 0 {
		return fmt.Errorf("%w: passes and lanes must be positive", ErrInvalidArgon2Parameters)
	}
	if bits.OnesCount32(p.MemoryKiB) != 1 {
		return fmt.Errorf("%w: memory %d KiB must be a power of two", ErrInvalidArgon2Parameters, p.MemoryKiB)
	}
	if uint64(p.MemoryKiB) < 8*uint64(p.Parallelism) {
		return fmt.Errorf("%w: memory %d KiB must be at least 8 KiB per lane", ErrInvalidArgon2Parameters, p.MemoryKiB)
	}
	return nil
}

func (p Argon2Parameters) checkLimits() error {
	switch {
	case p.MemoryKiB > MaxPasswordKDFMemoryKiB:
		return fmt.Errorf("%w: Argon2 memory %d KiB exceeds limit %d KiB", ErrPasswordKDFLimit, p.MemoryKiB, MaxPasswordKDFMemoryKiB)
	case p.Passes > MaxPasswordKDFPasses:
		return fmt.Errorf("%w: Argon2 passes %d exceeds limit %d", ErrPasswordKDFLimit, p.Passes, MaxPasswordKDFPasses)
	case p.Parallelism > MaxPasswordKDFLanes:
		return fmt.Errorf("%w: Argon2 lanes %d exceeds limit %d", ErrPasswordKDFLimit, p.Parallelism, MaxPasswordKDFLanes)
	}
	return nil
}

// OpenPGPPasswordEncryption holds a session key already wrapped by a password.
type OpenPGPPasswordEncryption struct {
	sessionKey []byte
	wrapper    []byte
}

// PreparePasswordOpenPGP derives the password key and serializes an AES-256
// SKESK v6 wrapper before any output is written.
func PreparePasswordOpenPGP(password []byte, params Argon2Parameters) (*OpenPGPPasswordEncryption, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		return nil, fmt.Errorf("generate OpenPGP session key: %w", err)
	}
	config := &packet.Config{
		DefaultCipher: packet.CipherAES256,
		AEADConfig:    &packet.AEADConfig{DefaultMode: packet.AEADModeGCM},
		S2KConfig: &s2k.Config{S2KMode: s2k.Argon2S2K, Argon2Config: &s2k.Argon2Config{
			NumberOfPasses:      uint8(params.Passes),      //nolint:gosec // Validate caps passes at 10.
			DegreeOfParallelism: uint8(params.Parallelism), //nolint:gosec // Validate caps lanes at 16.
			Memory:              params.MemoryKiB,
		}},
	}
	var wrapper bytes.Buffer
	if err := packet.SerializeSymmetricKeyEncryptedAEADReuseKey(&wrapper, sessionKey, password, true, config); err != nil {
		return nil, fmt.Errorf("wrap OpenPGP session key: %w", err)
	}
	return &OpenPGPPasswordEncryption{sessionKey: sessionKey, wrapper: wrapper.Bytes()}, nil
}

// Encrypt writes the password wrapper followed by an RFC 9580 AEAD packet stream.
func (e *OpenPGPPasswordEncryption) Encrypt(chunk uint32, input io.Reader, output io.Writer) error {
	if _, err := (shortWriterChecker{output}).Write(e.wrapper); err != nil {
		return fmt.Errorf("write OpenPGP password wrapper: %w", err)
	}
	return EncryptOpenPGP(e.sessionKey, chunk, input, output)
}

// OpenPGPPasswordMessage holds password wrappers whose KDF costs passed preflight.
type OpenPGPPasswordMessage struct {
	outer    *bufio.Reader
	source   *preparationBudget
	wrappers []*packet.SymmetricKeyEncrypted
}

// PrepareOpenPGPPassword reads a message's password wrappers and enforces KDF
// limits, per wrapper and cumulatively, before any password is requested.
func PrepareOpenPGPPassword(input io.Reader) (*OpenPGPPasswordMessage, error) {
	source, outer := newOpenPGPSource(input)
	message := &OpenPGPPasswordMessage{outer: outer, source: source}
	var work uint64
	for {
		tag, err := peekPacketTag(outer, 3, 18)
		if err != nil {
			return nil, err
		}
		if tag == 18 {
			break
		}
		if len(message.wrappers) == maxPasswordWrappers {
			return nil, fmt.Errorf("%w: more than %d password wrappers", errPasswordWrapper, maxPasswordWrappers)
		}
		wrapper, params, err := readPasswordWrapper(outer, source)
		if err != nil {
			return nil, err
		}
		if err := params.checkLimits(); err != nil {
			return nil, err
		}
		work += uint64(params.MemoryKiB) * uint64(params.Passes)
		if work > maxPasswordKDFWork {
			return nil, fmt.Errorf("%w: cumulative Argon2 cost %d KiB-passes across %d wrappers exceeds limit %d (%d MiB times %d passes)",
				ErrPasswordKDFLimit, work, len(message.wrappers)+1, maxPasswordKDFWork, MaxPasswordKDFMemoryKiB>>10, MaxPasswordKDFPasses)
		}
		message.wrappers = append(message.wrappers, wrapper)
	}
	if len(message.wrappers) == 0 {
		return nil, fmt.Errorf("%w: no password wrapper; decrypt with the message key", errPasswordWrapper)
	}
	return message, nil
}

// readPasswordWrapper parses one SKESK natively and reads its Argon2 costs
// from the same bytes, since go-crypto keeps them unexported.
func readPasswordWrapper(outer *bufio.Reader, source *preparationBudget) (*packet.SymmetricKeyEncrypted, Argon2Parameters, error) {
	var raw bytes.Buffer
	value, err := packet.Read(io.TeeReader(outer, &raw))
	if err != nil {
		if source.exceeded {
			return nil, Argon2Parameters{}, errOpenPGPHeaderBudget
		}
		return nil, Argon2Parameters{}, fmt.Errorf("read OpenPGP password wrapper: %w", err)
	}
	wrapper, ok := value.(*packet.SymmetricKeyEncrypted)
	if !ok || wrapper.Version != 6 || wrapper.CipherFunc != packet.CipherAES256 {
		return nil, Argon2Parameters{}, fmt.Errorf("%w: requires AES-256 SKESK v6", errPasswordWrapper)
	}
	body, err := packetBody(raw.Bytes())
	if err != nil {
		return nil, Argon2Parameters{}, err
	}
	// Body: version, count, cipher, AEAD mode, S2K length, then the S2K specifier.
	if len(body) < 5+argon2S2KLength || int(body[4]) != argon2S2KLength || s2k.Mode(body[5]) != s2k.Argon2S2K {
		return nil, Argon2Parameters{}, fmt.Errorf("%w: requires Argon2 S2K", errPasswordWrapper)
	}
	costs := body[5+1+s2k.Argon2SaltSize:]
	// packet.Read has already rejected memory exponents above 31.
	params := Argon2Parameters{MemoryKiB: 1 << costs[2], Passes: uint32(costs[0]), Parallelism: uint32(costs[1])}
	return wrapper, params, nil
}

// packetBody strips a definite-length header from one packet that packet.Read
// accepted. Partial and indeterminate lengths are not valid for SKESK.
func packetBody(raw []byte) ([]byte, error) {
	var size int
	switch {
	case len(raw) < 2:
		size = -1
	case raw[0]&0x40 == 0:
		size = map[byte]int{0: 2, 1: 3, 2: 5}[raw[0]&3]
	case raw[1] < 192:
		size = 2
	case raw[1] < 224:
		size = 3
	case raw[1] == 255:
		size = 6
	}
	if size <= 0 || size > len(raw) {
		return nil, fmt.Errorf("%w: packet length encoding", errPasswordWrapper)
	}
	return raw[size:], nil
}

// Open tries each wrapper with the password, then prepares the AEAD stream.
func (m *OpenPGPPasswordMessage) Open(password []byte) (*OpenPGPReader, error) {
	for _, wrapper := range m.wrappers {
		key, _, err := wrapper.Decrypt(password)
		if err != nil || len(key) != 32 {
			clear(key)
			continue
		}
		reader, err := prepareSEIPD(key, m.outer, m.source)
		clear(key)
		return reader, err
	}
	return nil, ErrOpenPGPPassword
}
