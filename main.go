// Command npc provides operator-friendly cryptographic utilities.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/sosheskaz-systems/npc/cmd"
)

func main() {
	os.Exit(run())
}

// run owns the signal context because os.Exit skips deferred calls.
func run() int {
	ctx, stop := cmd.WithInterrupt(context.Background())
	defer stop()

	err := cmd.ExecuteContext(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "npc: %v\n", err)
	}
	return cmd.ExitCode(err)
}
