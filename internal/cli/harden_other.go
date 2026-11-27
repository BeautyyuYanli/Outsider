//go:build !unix

package cli

// HardenProcess is a no-op on non-Unix platforms.
func HardenProcess() {}
