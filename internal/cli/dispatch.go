package cli

import (
	"errors"
	"fmt"
	"os"
)

func exitCodeOf(err error) int {
	var ce *CLIError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ExitConfigOrArg
}

func printRootHelp() {
	fmt.Fprintf(os.Stderr, `outsider %s — End-to-end encrypted out-of-band secret handoff CLI

Usage: outsider <command> [options]

Commands:
  init      Generate Ed25519 identity key & config.toml, printing relay.toml snippet
  id        Show device Ed25519 public key, fingerprint, and relay.toml snippet
  doctor    Check local config, relay connectivity, and Ed25519 allowlist status
  run       Request secret approval (Direct or SOPS) and execute target command
  name      Manage verified approval names in config.toml (add, ls, set, rm)
  sops      Manage SOPS (age) encrypted YAML secret files (keys, init, set, unset)

Flags:
  -h, --help      Show help
  -V, --version   Show version
`, Version)
}

// Run dispatches CLI arguments and returns the process exit code.
func Run(args []string) int {
	if len(args) == 0 {
		printRootHelp()
		return ExitConfigOrArg
	}
	switch args[0] {
	case "-h", "--help", "help":
		printRootHelp()
		return 0
	case "-V", "--version", "version":
		fmt.Printf("outsider %s\n", Version)
		return 0
	case "init":
		return runInit(args[1:])
	case "id":
		return runID(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "run":
		return runRun(args[1:])
	case "name":
		return runName(args[1:])
	case "sops":
		return runSops(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "[outsider] Unknown command: %q\n\n", args[0])
		printRootHelp()
		return ExitConfigOrArg
	}
}
