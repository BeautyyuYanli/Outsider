package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"outsider/internal/proto"
	"outsider/internal/sopsage"
)

func runSops(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		printSopsHelp()
		if len(args) == 0 {
			return ExitConfigOrArg
		}
		return 0
	}
	switch args[0] {
	case "keys":
		return runSopsKeys(args[1:])
	case "init":
		return runSopsInit(args[1:])
	case "set":
		return runSopsSet(args[1:])
	case "unset":
		return runSopsUnset(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "[outsider] Unknown `sops` subcommand: %q\n", args[0])
		printSopsHelp()
		return ExitConfigOrArg
	}
}

func printSopsHelp() {
	fmt.Fprintln(os.Stderr, `Usage: outsider sops <subcommand> [options]

Subcommands:
  keys <FILE>
      List plaintext leaf key paths inside a SOPS YAML file (local-only)
  init <FILE> --name <NAME> [--desc TEXT] [--reason TEXT] [--timeout SECS]
      Create a new SOPS YAML file (0 approvals if <NAME> is already registered; 1 approval with browser age-keygen support otherwise)
  set <FILE> <KEY>... [--name <NAME>] [--secret-name <SLUG>] [--stdin] [--reason TEXT] [--timeout SECS]
      Add or update one or more keys in a SOPS YAML file (collects new value(s) first, then unlocks SOPS_AGE_KEY last)
  unset <FILE> <KEY>... [--name <NAME>] [--reason TEXT] [--timeout SECS]
      Remove one or more keys from a SOPS YAML file`)
}

func runSopsKeys(args []string) int {
	fs := pflag.NewFlagSet("sops keys", pflag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		if err == pflag.ErrHelp {
			return 0
		}
		fmt.Fprintf(os.Stderr, "[outsider] Argument error: %v\n", err)
		return ExitConfigOrArg
	}
	pos := fs.Args()
	if len(pos) != 1 || strings.TrimSpace(pos[0]) == "" {
		fmt.Fprintln(os.Stderr, "[outsider] Usage: outsider sops keys <FILE>")
		return ExitConfigOrArg
	}
	expanded, err := ExpandTilde(strings.TrimSpace(pos[0]))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Error: %v\n", err)
		return ExitConfigOrArg
	}
	meta, err := sopsage.InspectFile(expanded)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] SOPS error: %v\n", err)
		return ExitConfigOrArg
	}
	for _, k := range meta.Keys {
		fmt.Println(k.Path)
	}
	return 0
}

func runSopsInit(args []string) int {
	fs := pflag.NewFlagSet("sops init", pflag.ContinueOnError)
	var (
		name    string
		desc    string
		reason  string
		timeout uint32
	)
	fs.StringVar(&name, "name", "", "Approval name for the SOPS age key (required)")
	fs.StringVar(&desc, "desc", "", "Optional description for the SOPS age key in config.toml")
	fs.StringVar(&reason, "reason", "", "Reason shown on notification and approval page")
	fs.Uint32Var(&timeout, "timeout", 0, "Approval timeout in seconds")

	if err := fs.Parse(args); err != nil {
		if err == pflag.ErrHelp {
			return 0
		}
		fmt.Fprintf(os.Stderr, "[outsider] Argument error: %v\n", err)
		return ExitConfigOrArg
	}
	pos := fs.Args()
	if len(pos) != 1 || strings.TrimSpace(pos[0]) == "" {
		fmt.Fprintln(os.Stderr, "[outsider] Usage: outsider sops init <FILE> --name <NAME> [--desc TEXT] [--reason TEXT] [--timeout SECS]")
		return ExitConfigOrArg
	}
	name = strings.TrimSpace(name)
	if name == "" {
		fmt.Fprintln(os.Stderr, "[outsider] Argument error: --name is required")
		return ExitConfigOrArg
	}

	displayFile := strings.TrimSpace(pos[0])
	expanded, err := ExpandTilde(displayFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Error: %v\n", err)
		return ExitConfigOrArg
	}
	if _, err := os.Stat(expanded); err == nil {
		fmt.Fprintf(os.Stderr, "[outsider] Error: file already exists: %s\n", displayFile)
		return ExitConfigOrArg
	}

	cfg, id, err := loadConfigAndIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
		return exitCodeOf(err)
	}
	defer id.Wipe()

	slug := proto.SlugifyName(name)

	// Fast path: if [names.<slug>] already exists with a verified sops_recipient, initialize locally (0 approvals).
	if existing, ok := cfg.Names[slug]; ok {
		if !existing.IsSops() {
			fmt.Fprintf(os.Stderr, "[outsider] Config error: name %q is already registered as a Direct secret\n", slug)
			return ExitConfigOrArg
		}
		recipient := strings.TrimSpace(existing.SopsRecipient)
		if err := sopsage.ValidateRecipient(recipient); err != nil {
			fmt.Fprintf(os.Stderr, "[outsider] Config error: %v\n", err)
			return ExitConfigOrArg
		}
		if err := sopsage.InitFile(expanded, []string{recipient}); err != nil {
			fmt.Fprintf(os.Stderr, "[outsider] SOPS error: %v\n", err)
			return ExitConfigOrArg
		}
		if fs.Changed("desc") {
			if err := saveSopsName(slug, recipient, desc, true); err != nil {
				fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
				return exitCodeOf(err)
			}
		}
		fmt.Printf("Initialized : %s (0600)\n", expanded)
		fmt.Printf("Name        : %s\n", slug)
		fmt.Printf("Recipient   : %s\n", recipient)
		return 0
	}

	// First-time enrollment: 1 approval for SOPS_AGE_KEY (Web page shows on-demand "Generate age key" button).
	ttl := cfg.DefaultTimeoutSecs
	if fs.Changed("timeout") && timeout > 0 {
		ttl = timeout
	}
	if strings.TrimSpace(reason) == "" {
		reason = fmt.Sprintf("Initialize SOPS secret store %s", displayFile)
	}

	client := NewRelayClient(cfg.RelayURL)
	ageKey, err := client.RequestSecret(context.Background(), id, proto.Context{
		Name:           slug,
		Reason:         reason,
		CommandSummary: fmt.Sprintf("[sops:init %s]", displayFile),
	}, ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
		return exitCodeOf(err)
	}
	defer clear(ageKey)

	ageID, err := sopsage.ParseAgeIdentity(ageKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] SOPS key error: %v\n", err)
		return ExitCrypto
	}
	recipient := ageID.Recipient().String()

	if err := cfg.CheckRecipientUnique(slug, recipient); err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Config error: %v\n", err)
		return ExitConfigOrArg
	}

	if err := sopsage.InitFile(expanded, []string{recipient}); err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] SOPS error: %v\n", err)
		return ExitConfigOrArg
	}
	// Verify round-trip decryption before registering name.
	if kvs, err := sopsage.Decrypt(expanded, ageKey, nil); err != nil {
		_ = os.Remove(expanded)
		fmt.Fprintf(os.Stderr, "[outsider] SOPS verification error: %v\n", err)
		return ExitCrypto
	} else {
		sopsage.WipeKVs(kvs)
	}
	clear(ageKey)

	if err := saveSopsName(slug, recipient, desc, fs.Changed("desc")); err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
		return exitCodeOf(err)
	}

	fmt.Printf("Initialized : %s (0600)\n", expanded)
	fmt.Printf("Name        : %s\n", slug)
	fmt.Printf("Recipient   : %s\n", recipient)
	fmt.Printf("Bitwarden   : /approve/%s/\n", slug)
	return 0
}

func runSopsSet(args []string) int {
	fs := pflag.NewFlagSet("sops set", pflag.ContinueOnError)
	var (
		name       string
		secretName string
		fromStdin  bool
		reason     string
		timeout    uint32
	)
	fs.StringVar(&name, "name", "", "Approval name for SOPS_AGE_KEY (auto-resolved from config.toml when registered)")
	fs.StringVar(&secretName, "secret-name", "", "Override approval name for the new key value (single key only)")
	fs.BoolVar(&fromStdin, "stdin", false, "Read the new key value from stdin instead of requesting a value approval (single key only)")
	fs.StringVar(&reason, "reason", "", "Reason shown on notification and approval page")
	fs.Uint32Var(&timeout, "timeout", 0, "Approval timeout in seconds")

	if err := fs.Parse(args); err != nil {
		if err == pflag.ErrHelp {
			return 0
		}
		fmt.Fprintf(os.Stderr, "[outsider] Argument error: %v\n", err)
		return ExitConfigOrArg
	}
	pos := fs.Args()
	if len(pos) < 2 {
		fmt.Fprintln(os.Stderr, "[outsider] Usage: outsider sops set <FILE> <KEY>... [--name <NAME>] [--secret-name <SLUG>] [--stdin] [--reason TEXT] [--timeout SECS]")
		return ExitConfigOrArg
	}

	displayFile := strings.TrimSpace(pos[0])
	keys := pos[1:]
	if len(keys) > 1 {
		if fs.Changed("secret-name") {
			fmt.Fprintln(os.Stderr, "[outsider] Argument error: --secret-name is only allowed when setting a single key")
			return ExitConfigOrArg
		}
		if fromStdin {
			fmt.Fprintln(os.Stderr, "[outsider] Argument error: --stdin is only allowed when setting a single key")
			return ExitConfigOrArg
		}
	}
	for i, k := range keys {
		k = strings.TrimSpace(k)
		if _, err := sopsage.ValidateKeyPath(k); err != nil {
			fmt.Fprintf(os.Stderr, "[outsider] Argument error: %v\n", err)
			return ExitConfigOrArg
		}
		keys[i] = k
	}

	expanded, err := ExpandTilde(displayFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Error: %v\n", err)
		return ExitConfigOrArg
	}
	meta, err := sopsage.InspectFile(expanded)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] SOPS error: %v\n", err)
		return ExitConfigOrArg
	}

	cfg, id, err := loadConfigAndIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
		return exitCodeOf(err)
	}
	defer id.Wipe()

	approvalName := strings.TrimSpace(name)
	if approvalName == "" {
		resolved, err := cfg.ResolveSopsName(meta.Recipients)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
			return ExitConfigOrArg
		}
		approvalName = resolved
	}

	ttl := cfg.DefaultTimeoutSecs
	if fs.Changed("timeout") && timeout > 0 {
		ttl = timeout
	}
	client := NewRelayClient(cfg.RelayURL)
	ctx := context.Background()

	// Step 1: Collect new value(s) FIRST so SOPS_AGE_KEY only stays in RAM for milliseconds at the end.
	updates := make([]sopsage.KV, 0, len(keys))
	defer sopsage.WipeKVs(updates)

	if fromStdin {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[outsider] Read stdin error: %v\n", err)
			return ExitConfigOrArg
		}
		// Trim at most one trailing line ending (standard for piped echo / openssl rand).
		val := bytes.TrimSuffix(raw, []byte("\n"))
		val = bytes.TrimSuffix(val, []byte("\r"))
		updates = append(updates, sopsage.KV{Key: keys[0], Value: val})
	} else {
		for _, k := range keys {
			valApprovalName := proto.SlugifyName(k)
			if len(keys) == 1 && strings.TrimSpace(secretName) != "" {
				valApprovalName = strings.TrimSpace(secretName)
			}
			valReason := reason
			if strings.TrimSpace(valReason) == "" {
				valReason = fmt.Sprintf("Provide value for %s in %s", k, displayFile)
			}
			val, err := client.RequestSecret(ctx, id, proto.Context{
				Name:           valApprovalName,
				Reason:         valReason,
				CommandSummary: fmt.Sprintf("[sops:set-value %s key=%s]", displayFile, k),
			}, ttl)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
				return exitCodeOf(err)
			}
			updates = append(updates, sopsage.KV{Key: k, Value: val})
		}
	}

	// Step 2 (last): Unlock SOPS_AGE_KEY once, encrypt all updates, recompute MAC, atomic rename, wipe.
	keySummary := fmt.Sprintf("[sops:set %s keys=%s]", displayFile, strings.Join(keys, ","))
	if fromStdin {
		keySummary = fmt.Sprintf("[sops:set %s key=%s (from stdin)]", displayFile, keys[0])
	}
	unlockReason := reason
	if strings.TrimSpace(unlockReason) == "" {
		unlockReason = fmt.Sprintf("Update %s in %s", strings.Join(keys, ", "), displayFile)
	}
	ageKey, err := client.RequestSecret(ctx, id, proto.Context{
		Name:           approvalName,
		Reason:         unlockReason,
		CommandSummary: keySummary,
	}, ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
		return exitCodeOf(err)
	}
	defer clear(ageKey)

	if err := sopsage.SetKeys(expanded, ageKey, updates); err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] SOPS set error: %v\n", err)
		if errors.Is(err, sopsage.ErrDecrypt) {
			return ExitCrypto
		}
		return ExitConfigOrArg
	}
	clear(ageKey)
	sopsage.WipeKVs(updates)

	fmt.Printf("Updated %s: %s\n", displayFile, strings.Join(keys, ", "))
	return 0
}

func runSopsUnset(args []string) int {
	fs := pflag.NewFlagSet("sops unset", pflag.ContinueOnError)
	var (
		name    string
		reason  string
		timeout uint32
	)
	fs.StringVar(&name, "name", "", "Approval name for SOPS_AGE_KEY (auto-resolved from config.toml when registered)")
	fs.StringVar(&reason, "reason", "", "Reason shown on notification and approval page")
	fs.Uint32Var(&timeout, "timeout", 0, "Approval timeout in seconds")

	if err := fs.Parse(args); err != nil {
		if err == pflag.ErrHelp {
			return 0
		}
		fmt.Fprintf(os.Stderr, "[outsider] Argument error: %v\n", err)
		return ExitConfigOrArg
	}
	pos := fs.Args()
	if len(pos) < 2 {
		fmt.Fprintln(os.Stderr, "[outsider] Usage: outsider sops unset <FILE> <KEY>... [--name <NAME>] [--reason TEXT] [--timeout SECS]")
		return ExitConfigOrArg
	}

	displayFile := strings.TrimSpace(pos[0])
	keys := pos[1:]
	expanded, err := ExpandTilde(displayFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Error: %v\n", err)
		return ExitConfigOrArg
	}
	meta, err := sopsage.InspectFile(expanded)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] SOPS error: %v\n", err)
		return ExitConfigOrArg
	}

	for i, k := range keys {
		k = strings.TrimSpace(k)
		if _, err := sopsage.ValidateKeyPath(k); err != nil {
			fmt.Fprintf(os.Stderr, "[outsider] Argument error: %v\n", err)
			return ExitConfigOrArg
		}
		if !meta.KeySet[k] {
			fmt.Fprintf(os.Stderr, "[outsider] SOPS error: key %q not found in %s\n", k, displayFile)
			return ExitConfigOrArg
		}
		keys[i] = k
	}

	cfg, id, err := loadConfigAndIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
		return exitCodeOf(err)
	}
	defer id.Wipe()

	approvalName := strings.TrimSpace(name)
	if approvalName == "" {
		resolved, err := cfg.ResolveSopsName(meta.Recipients)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
			return ExitConfigOrArg
		}
		approvalName = resolved
	}

	ttl := cfg.DefaultTimeoutSecs
	if fs.Changed("timeout") && timeout > 0 {
		ttl = timeout
	}
	if strings.TrimSpace(reason) == "" {
		reason = fmt.Sprintf("Remove %s from %s", strings.Join(keys, ", "), displayFile)
	}

	client := NewRelayClient(cfg.RelayURL)
	ageKey, err := client.RequestSecret(context.Background(), id, proto.Context{
		Name:           approvalName,
		Reason:         reason,
		CommandSummary: fmt.Sprintf("[sops:unset %s keys=%s]", displayFile, strings.Join(keys, ",")),
	}, ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
		return exitCodeOf(err)
	}
	defer clear(ageKey)

	if err := sopsage.UnsetKeys(expanded, ageKey, keys); err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] SOPS unset error: %v\n", err)
		if errors.Is(err, sopsage.ErrDecrypt) {
			return ExitCrypto
		}
		return ExitConfigOrArg
	}
	clear(ageKey)

	fmt.Printf("Removed from %s: %s\n", displayFile, strings.Join(keys, ", "))
	return 0
}
