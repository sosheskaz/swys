package contextio_test

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/sosheskaz-systems/npc/internal/contextio"
)

func ExampleNewOwnedFileReader() {
	input, output, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	if _, err := output.WriteString("request body"); err != nil {
		panic(err)
	}
	if err := output.Close(); err != nil {
		panic(err)
	}

	reader, err := contextio.NewOwnedFileReader(context.Background(), input)
	if err != nil {
		panic(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		panic(err)
	}
	if err := reader.Close(); err != nil {
		panic(err)
	}

	fmt.Println(string(data))
	// Output: request body
}
