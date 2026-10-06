package aes

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/password"
	"github.com/sosheskaz/swys/internal/crypter"
)

const (
	passwordFlagName   = "password"
	kdfMemoryFlag      = "kdf-memory"
	kdfPassesFlag      = "kdf-passes"
	kdfParallelismFlag = "kdf-parallelism"
)

var (
	errPasswordFalse  = errors.New("--password=false does not select a password source")
	errPasswordFlag   = errors.New("invalid password flag")
	errKDFMemory      = errors.New("invalid --kdf-memory")
	errKDFPasses      = errors.New("invalid --kdf-passes")
	errKDFParallelism = errors.New("invalid --kdf-parallelism")
)

var passwordSources = []string{passwordFlagName, "password-command", "password-env"}

func passwordSelected(cmd *cobra.Command) bool {
	for _, name := range passwordSources {
		if cmd.Flags().Changed(name) {
			return true
		}
	}
	return false
}

func addPasswordFlags(cmd *cobra.Command) {
	cmd.Flags().Bool(passwordFlagName, false, "prompt for a password on the controlling terminal")
	registerAESValueCompletion(cmd, passwordFlagName, func() []string { return []string{"true"} })
	cmd.Flags().String("password-command", "", "run a shell command whose first output line is the password")
	cmd.Flags().String("password-env", "", "read a password from this named environment variable")
	registerAESNoFileFlagCompletion(cmd, "password-command")
	registerAESNoFileFlagCompletion(cmd, "password-env")
}

func addPasswordCostFlags(cmd *cobra.Command) {
	cmd.Flags().String(kdfMemoryFlag, "64MiB", "Argon2id memory cost (power of two KiB, at most 256MiB)")
	cmd.Flags().String(kdfPassesFlag, "3", "Argon2id pass count (at most 10)")
	cmd.Flags().String(kdfParallelismFlag, "4", "Argon2id lanes (at most 16)")
	for _, name := range []string{kdfMemoryFlag, kdfPassesFlag, kdfParallelismFlag} {
		registerAESNoFileFlagCompletion(cmd, name)
	}
}

// validateAESPasswordFlags checks password flag combinations and KDF costs
// before any password is requested or output is opened.
func validateAESPasswordFlags(cmd *cobra.Command) error {
	if cmd.Flags().Changed(passwordFlagName) {
		enabled, err := cmd.Flags().GetBool(passwordFlagName)
		if err != nil {
			return fmt.Errorf("read --password: %w", err)
		}
		if !enabled {
			return errPasswordFalse
		}
	}
	costFlags := []string{kdfMemoryFlag, kdfPassesFlag, kdfParallelismFlag}
	if !passwordSelected(cmd) {
		for _, name := range costFlags {
			if flag := cmd.Flags().Lookup(name); flag != nil && flag.Changed {
				return fmt.Errorf("%w: --%s requires a password source", errPasswordFlag, name)
			}
		}
		return nil
	}
	wire, err := getAESString(cmd, "wire-format")
	if err != nil {
		return err
	}
	if wire != wireOpenPGP {
		return fmt.Errorf("%w: passwords require --wire-format %s", errPasswordFlag, wireOpenPGP)
	}
	for _, name := range []string{"key-format", "key-id", flagAAD, flagHKDFHash, flagDerivedBits} {
		if cmd.Flags().Changed(name) {
			return fmt.Errorf("%w: --%s cannot be used with a password; passwords use OpenPGP AES-256", errPasswordFlag, name)
		}
	}
	if cmd.Name() == commandDecrypt {
		return nil
	}
	_, err = aesPasswordParameters(cmd)
	return err
}

func aesPasswordParameters(cmd *cobra.Command) (crypter.Argon2Parameters, error) {
	memory, err := getAESString(cmd, kdfMemoryFlag)
	if err != nil {
		return crypter.Argon2Parameters{}, err
	}
	memoryKiB, err := parseKDFMemory(memory)
	if err != nil {
		return crypter.Argon2Parameters{}, err
	}
	passes, err := parseKDFCount(cmd, kdfPassesFlag, errKDFPasses)
	if err != nil {
		return crypter.Argon2Parameters{}, err
	}
	lanes, err := parseKDFCount(cmd, kdfParallelismFlag, errKDFParallelism)
	if err != nil {
		return crypter.Argon2Parameters{}, err
	}
	params := crypter.Argon2Parameters{MemoryKiB: memoryKiB, Passes: passes, Parallelism: lanes}
	if err := params.Validate(); err != nil {
		return params, fmt.Errorf("invalid Argon2id cost: %w", err)
	}
	return params, nil
}

func parseKDFMemory(value string) (uint32, error) {
	amount, suffix, ok := splitAESChunkSize(value)
	if !ok {
		return 0, fmt.Errorf("%w %q", errKDFMemory, value)
	}
	multipliers := map[string]int64{
		"": 1, "B": 1, "K": 1024, "KIB": 1024, "M": 1024 * 1024, "MIB": 1024 * 1024,
		"G": 1024 * 1024 * 1024, "GIB": 1024 * 1024 * 1024, "KB": 1000, "MB": 1000000, "GB": 1000000000,
	}
	multiplier, ok := multipliers[suffix]
	if !ok {
		return 0, fmt.Errorf("%w unit %q", errKDFMemory, suffix)
	}
	size, ok := new(big.Rat).SetString(amount)
	if !ok {
		return 0, fmt.Errorf("%w %q", errKDFMemory, value)
	}
	size.Mul(size, big.NewRat(multiplier, 1024))
	if !size.IsInt() || size.Num().Sign() <= 0 {
		return 0, fmt.Errorf("%w %q: must be a positive power of two KiB", errKDFMemory, value)
	}
	if size.Num().Cmp(big.NewInt(crypter.MaxPasswordKDFMemoryKiB)) > 0 {
		return 0, fmt.Errorf("%w: Argon2 memory %s KiB exceeds limit %d KiB",
			crypter.ErrPasswordKDFLimit, size.Num(), crypter.MaxPasswordKDFMemoryKiB)
	}
	return uint32(size.Num().Uint64()), nil //nolint:gosec // bounded by the memory limit above
}

func parseKDFCount(cmd *cobra.Command, name string, invalid error) (uint32, error) {
	text, err := getAESString(cmd, name)
	if err != nil {
		return 0, err
	}
	count, err := strconv.ParseUint(text, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w %q", invalid, text)
	}
	return uint32(count), nil
}

func acquireAESPassword(cmd *cobra.Command) ([]byte, error) {
	if cmd.Flags().Changed(passwordFlagName) {
		return password.Prompt(cmd.Context(), cmd.Name() != commandDecrypt)
	}
	if cmd.Flags().Changed("password-command") {
		script, err := getAESString(cmd, "password-command")
		if err != nil {
			return nil, err
		}
		return password.Command(cmd.Context(), script, cmd.ErrOrStderr())
	}
	name, err := getAESString(cmd, "password-env")
	if err != nil {
		return nil, err
	}
	return password.Environment(name)
}

// prepareAESPassword derives password keys during input preparation. For
// decryption it checks stored KDF costs before asking for the password.
func prepareAESPassword(cmd *cobra.Command, op *aesOperation) error {
	var message *crypter.OpenPGPPasswordMessage
	if cmd.Name() == commandDecrypt {
		input, err := commandio.CommandInput(cmd, cmd.Flags().Args())
		if err != nil {
			return err
		}
		op.input = input
		message, err = crypter.PrepareOpenPGPPassword(input)
		if err != nil {
			return err
		}
	}
	secret, err := acquireAESPassword(cmd)
	if err != nil {
		return fmt.Errorf("acquire password: %w", err)
	}
	defer clear(secret)
	if message != nil {
		op.pgp, err = message.Open(secret)
		return err
	}
	params, err := aesPasswordParameters(cmd)
	if err != nil {
		return err
	}
	op.password, err = crypter.PreparePasswordOpenPGP(secret, params)
	return err
}
