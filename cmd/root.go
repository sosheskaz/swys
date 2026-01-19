package cmd

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use: "cryptool",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		handleIORedirection(cmd)

		outputFlag := cmd.Flags().Lookup("format")
		if outputFlag.Changed {
			format, err := cmd.Flags().GetString("format")
			dieIf(err)

			switch format {
			case "base64", "b64":
				b64Filter(cmd)
			}
		}
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func dieIf(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "encountered fatal error: %v\n", err)
		os.Exit(1)
	}
}

func dieIfT[T any](val T, err error) T {
	dieIf(err)
	return val
}

func generateIV(blockSize int) []byte {
	iv := make([]byte, blockSize)
	_ = dieIfT(io.ReadFull(rand.Reader, iv))
	return iv
}

func handleIORedirection(cmd *cobra.Command) error {
	if i, err := cmd.Flags().GetString("input"); err != nil {
		return fmt.Errorf("failed to read input flag: %w", err)
	} else if i != "" {
		if f, err := os.Open(i); err != nil {
			return fmt.Errorf("failed to open %s for reading: %w", i, err)
		} else {
			cmd.SetIn(f)
		}
	}

	if o, err := cmd.Flags().GetString("output"); err != nil {
		return fmt.Errorf("failed to read output flag: %w", err)
	} else if o != "" {
		f, err := os.OpenFile(o, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open %s for writing: %w", o, err)
		}
		cmd.SetOut(f)
	}

	return nil
}

func init() {
	rootCmd.PersistentFlags().StringP("format", "f", "raw", "format to use for input and output data (base64, hex, raw).")

	rootCmd.PersistentFlags().StringP("input", "i", "", "Redirect stdin to read from this file.")
	rootCmd.MarkFlagFilename("input")
	rootCmd.PersistentFlags().StringP("output", "o", "", "Redirect stdout to write to this file.")
	rootCmd.MarkFlagFilename("output")
}
