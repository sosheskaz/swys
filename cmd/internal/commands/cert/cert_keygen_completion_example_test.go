package cert_test

import (
	"bytes"
	"fmt"
	"strings"

	rootcmd "github.com/sosheskaz-systems/npc/cmd"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
)

func Example_certKeygenCompletion() {
	root := rootcmd.NewCommand()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"__complete", "cert", "keygen", "--algorithm", ""})
	err := commandio.Execute(root)
	if err != nil {
		panic(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		if strings.HasPrefix(line, "ed25519") {
			fmt.Println(line)
		}
	}
	// Output:
	// ed25519	Ed25519 signing key
}
