//go:build unix

package cli

import (
	"fmt"
	"os/exec"
	"syscall"
)

// replaceProcess execs argv[0] in place so the parent outsider process exits with zero lingering memory.
func replaceProcess(argv []string, env []string) error {
	bin, err := exec.LookPath(argv[0])
	if err != nil {
		return fmt.Errorf("failed to find target command %q: %w", argv[0], err)
	}
	return syscall.Exec(bin, argv, env)
}
