package cli

import "fmt"

// Standard Outsider CLI exit codes.
const (
	ExitConfigOrArg = 100
	ExitRelayOrAuth = 101
	ExitExpired     = 102
	ExitCrypto      = 103
)

// CLIError carries a deterministic exit code alongside a human-readable error message.
type CLIError struct {
	Code int
	Msg  string
}

func (e *CLIError) Error() string {
	return e.Msg
}

func errConfig(format string, args ...any) *CLIError {
	return &CLIError{Code: ExitConfigOrArg, Msg: fmt.Sprintf(format, args...)}
}

func errRelay(format string, args ...any) *CLIError {
	return &CLIError{Code: ExitRelayOrAuth, Msg: fmt.Sprintf(format, args...)}
}

func errExpired(format string, args ...any) *CLIError {
	return &CLIError{Code: ExitExpired, Msg: fmt.Sprintf(format, args...)}
}

func errCrypto(format string, args ...any) *CLIError {
	return &CLIError{Code: ExitCrypto, Msg: fmt.Sprintf(format, args...)}
}
