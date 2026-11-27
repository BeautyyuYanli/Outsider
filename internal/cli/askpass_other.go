//go:build !unix

package cli

import (
	"errors"
	"os"
)

// MaybeRunAskpassHelper is a no-op on non-Unix platforms.
func MaybeRunAskpassHelper() {}

type askpassGuard struct{}

func (g *askpassGuard) Close() {}

func startAskpassServer(_ []byte) (*askpassGuard, map[string]string, error) {
	return nil, nil, errors.New("--askpass is only supported on Unix platforms")
}

func preferredTempDir() string {
	return os.TempDir()
}
