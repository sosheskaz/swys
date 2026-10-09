// Command swys provides operator-friendly cryptographic utilities.
package main

import (
	"context"
	"os"

	"github.com/sosheskaz/swys/cmd"
)

func main() {
	os.Exit(run())
}

// run owns the signal context because os.Exit skips deferred calls.
func run() int {
	ctx, stop := cmd.WithInterrupt(context.Background())
	defer stop()

	err := cmd.ExecuteContextWithDiagnostics(ctx)
	return cmd.ExitCode(err)
}
