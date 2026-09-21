package contextio_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sosheskaz-systems/npc/internal/contextio"
)

var errInterrupted = errors.New("interrupted")

// A read from an idle stdin returns as soon as the context is canceled.
func ExampleNewReader() {
	ctx, cancel := context.WithCancelCause(context.Background())
	idle, writer := io.Pipe()
	defer writer.CloseWithError(nil)
	go cancel(errInterrupted)

	_, err := contextio.NewReader(ctx, idle).Read(make([]byte, 8))
	fmt.Println(errors.Is(err, errInterrupted))
	// Output: true
}

// An open that would block, such as a FIFO with no writer, stops waiting once
// the context is canceled.
func ExampleOpenFile() {
	ctx, cancel := context.WithCancelCause(context.Background())
	blocked := make(chan struct{})
	defer close(blocked)
	go cancel(errInterrupted)

	_, err := contextio.OpenFile(ctx, func() (*os.File, error) {
		<-blocked
		return nil, os.ErrNotExist
	})
	fmt.Println(errors.Is(err, errInterrupted))
	// Output: true
}
