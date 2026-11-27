//go:build !unix

package cli

import "errors"

var errExecUnsupported = errors.New("syscall.Exec unsupported on this platform")

func replaceProcess(_ []string, _ []string) error {
	return errExecUnsupported
}
