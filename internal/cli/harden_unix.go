//go:build unix && !linux

package cli

import "syscall"

// HardenProcess disables core dumps on Unix platforms.
func HardenProcess() {
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
}
