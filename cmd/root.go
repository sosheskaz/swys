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

func init() {
	rootCmd.PersistentFlags().StringP("format", "f", "raw", "format to use for input and output data (base64, hex, raw).")
}
