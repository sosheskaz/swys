package aes

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/sosheskaz-systems/npc/internal/crypter"
)

func parseAESChunkSize(value string) (uint32, error) {
	amount, suffix, ok := splitAESChunkSize(value)
	if !ok {
		return 0, fmt.Errorf("%w %q", errInvalidAESChunkSize, value)
	}
	multipliers := map[string]int64{
		"": 1, "B": 1,
		"K": 1024, "M": 1024 * 1024, "G": 1024 * 1024 * 1024,
		"KIB": 1024, "MIB": 1024 * 1024, "GIB": 1024 * 1024 * 1024,
		"KB": 1000, "MB": 1000 * 1000, "GB": 1000 * 1000 * 1000,
	}
	multiplier, ok := multipliers[suffix]
	if !ok {
		return 0, fmt.Errorf("%w unit %q", errInvalidAESChunkSize, suffix)
	}
	rational, ok := new(big.Rat).SetString(amount)
	if !ok {
		return 0, fmt.Errorf("%w %q", errInvalidAESChunkSize, value)
	}
	rational.Mul(rational, big.NewRat(multiplier, 1))
	if !rational.IsInt() || rational.Num().Cmp(big.NewInt(crypter.MinAESChunkSize)) < 0 || rational.Num().Cmp(big.NewInt(crypter.MaxAESChunkSize)) > 0 {
		return 0, fmt.Errorf("%w %q: must be an integral byte count from %d through %d",
			errInvalidAESChunkSize, value, crypter.MinAESChunkSize, crypter.MaxAESChunkSize)
	}
	parsed, err := strconv.ParseUint(rational.Num().String(), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w %q: %w", errInvalidAESChunkSize, value, err)
	}
	return uint32(parsed), nil
}

func splitAESChunkSize(value string) (string, string, bool) {
	cut := 0
	for cut < len(value) && (value[cut] >= '0' && value[cut] <= '9' || value[cut] == '.') {
		cut++
	}
	amount := value[:cut]
	if amount == "" || strings.Count(amount, ".") > 1 || strings.HasPrefix(amount, ".") || strings.HasSuffix(amount, ".") {
		return "", "", false
	}
	return amount, strings.ToUpper(value[cut:]), true
}
