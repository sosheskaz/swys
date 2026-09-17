package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

func Example_keyCompletion() {
	root := newRootCmd()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"__complete", "key", "generate", "--public-out", "public.pem", ""})
	command, runErr := root.ExecuteC()
	err := errors.Join(runErr, closeCommandIO(command))
	if err != nil {
		panic(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		if strings.HasPrefix(line, "ed25519") || strings.HasPrefix(line, "aes128") {
			fmt.Println(line)
		}
	}
	// Output:
	// ed25519	Ed25519 signing key
}
