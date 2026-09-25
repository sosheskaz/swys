package key_test

import (
	"bytes"
	"fmt"
	"strings"

	rootcmd "github.com/sosheskaz-systems/npc/cmd"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
)

func Example_keyCompletion() {
	root := rootcmd.NewCommand()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"__complete", "key", "generate", "--public-out", "public.pem", ""})
	err := commandio.Execute(root)
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
