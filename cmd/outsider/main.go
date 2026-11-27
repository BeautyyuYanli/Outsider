package main

import (
	"os"

	"outsider/internal/cli"
)

func main() {
	// Must run first: handle self-invocation by ssh/git/sudo in --askpass mode.
	cli.MaybeRunAskpassHelper()

	// Disable core dumps and ptrace inspection before touching any key material.
	cli.HardenProcess()

	os.Exit(cli.Run(os.Args[1:]))
}
