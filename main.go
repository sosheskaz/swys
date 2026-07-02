// Command cryptool provides operator-friendly cryptographic utilities.
package main

import (
	"fmt"
	"os"

	"github.com/sosheskaz/cryptool/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "cryptool: %v\n", err)
		os.Exit(1)
	}
}
