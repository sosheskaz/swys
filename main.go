// Command npc provides operator-friendly cryptographic utilities.
package main

import (
	"fmt"
	"os"

	"github.com/sosheskaz-systems/npc/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "npc: %v\n", err)
		os.Exit(1)
	}
}
