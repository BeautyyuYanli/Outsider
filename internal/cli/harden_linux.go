//go:build linux

package cli

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// HardenProcess disables core dumps and ptrace/mem inspection by non-root same-UID processes.
func HardenProcess() {
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
