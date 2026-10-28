package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/picatz/doh/internal/cli"
)

func main() {
	// SIGTERM is how service managers and container runtimes ask a process
	// to stop, so handle it like an interrupt for a graceful shutdown.
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer cancel()

	err := cli.CommandRoot.ExecuteContext(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
