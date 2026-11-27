package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/pflag"

	"outsider/internal/proto"
	"outsider/internal/sopsage"
)

func runName(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		printNameHelp()
		if len(args) == 0 {
			return ExitConfigOrArg
		}
		return 0
	}
	switch args[0] {
	case "add":
		return runNameAdd(args[1:])
	case "ls", "list":
		return runNameLS(args[1:])
	case "set":
		return runNameSet(args[1:])
	case "rm", "remove":
		return runNameRM(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "[outsider] Unknown `name` subcommand: %q\n", args[0])
		printNameHelp()
		return ExitConfigOrArg
	}
}

func printNameHelp() {
	fmt.Fprintln(os.Stderr, `Usage: outsider name <subcommand> [options]

Subcommands:
  add <NAME> [--sops] [--desc TEXT] [--reason TEXT] [--timeout SECS]
      Enroll a new verified approval name via a real human approval request
  ls
      List all registered Direct and SOPS approval names in config.toml
  set <NAME> --desc TEXT
      Update metadata (description) for an existing registered name (local-only)
  rm <NAME>
      Remove a registered name from config.toml (local-only)`)
}

func runNameAdd(args []string) int {
	fs := pflag.NewFlagSet("name add", pflag.ContinueOnError)
	var (
		isSops  bool
		desc    string
		reason  string
		timeout uint32
	)
	fs.BoolVar(&isSops, "sops", false, "Register a SOPS age private key (derives and binds age1... public key)")
	fs.StringVar(&desc, "desc", "", "Human/Agent-readable description for this name")
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
		fmt.Fprintln(os.Stderr, "[outsider] Usage: outsider name add <NAME> [--sops] [--desc TEXT] [--reason TEXT] [--timeout SECS]")
		return ExitConfigOrArg
	}

	slug := proto.SlugifyName(pos[0])
	cfg, id, err := loadConfigAndIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
		return exitCodeOf(err)
	}
	defer id.Wipe()

	if _, exists := cfg.Names[slug]; exists {
		fmt.Fprintf(os.Stderr, "[outsider] Error: name %q is already registered (use `outsider name set %s --desc ...` or `outsider name rm %s`)\n", slug, slug, slug)
		return ExitConfigOrArg
	}

	ttl := cfg.DefaultTimeoutSecs
	if fs.Changed("timeout") && timeout > 0 {
		ttl = timeout
	}

	cmdSummary := "[register-name] " + slug
	if isSops {
		cmdSummary = "[register-sops-key] " + slug
	}
	if strings.TrimSpace(reason) == "" {
		if isSops {
			reason = "Register and verify SOPS age key"
		} else {
			reason = "Register and verify approval name"
		}
	}

	client := NewRelayClient(cfg.RelayURL)
	secret, err := client.RequestSecret(context.Background(), id, proto.Context{
		Name:           slug,
		Reason:         reason,
		CommandSummary: cmdSummary,
	}, ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
		return exitCodeOf(err)
	}
	defer clear(secret)

	if len(strings.TrimSpace(string(secret))) == 0 {
		fmt.Fprintln(os.Stderr, "[outsider] Error: approved secret payload is empty")
		return ExitCrypto
	}

	var recipient string
	if isSops {
		ageID, err := sopsage.ParseAgeIdentity(secret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[outsider] Error: %v\n", err)
			return ExitCrypto
		}
		recipient = ageID.Recipient().String()
	}
	clear(secret)

	if isSops {
		if err := saveSopsName(slug, recipient, desc, fs.Changed("desc")); err != nil {
			fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
			return exitCodeOf(err)
		}
	} else {
		rawCfg, err := LoadRawConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[outsider] Config error: %v\n", err)
			return ExitConfigOrArg
		}
		if _, exists := rawCfg.Names[slug]; exists {
			fmt.Fprintf(os.Stderr, "[outsider] Error: name %q already exists\n", slug)
			return ExitConfigOrArg
		}
		rawCfg.Names[slug] = NameEntry{Description: strings.TrimSpace(desc)}
		if _, err := SaveConfig(rawCfg); err != nil {
			fmt.Fprintf(os.Stderr, "[outsider] Config error: %v\n", err)
			return ExitConfigOrArg
		}
	}

	fmt.Printf("Registered  : %s\n", slug)
	if isSops {
		fmt.Println("Type        : sops")
		fmt.Printf("Recipient   : %s\n", recipient)
	} else {
		fmt.Println("Type        : direct")
	}
	fmt.Printf("Bitwarden   : /approve/%s/\n", slug)
	if strings.TrimSpace(desc) != "" {
		fmt.Printf("Description : %s\n", strings.TrimSpace(desc))
	}
	return 0
}

func runNameLS(args []string) int {
	fs := pflag.NewFlagSet("name ls", pflag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		if err == pflag.ErrHelp {
			return 0
		}
		fmt.Fprintf(os.Stderr, "[outsider] Argument error: %v\n", err)
		return ExitConfigOrArg
	}
	cfg, err := LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Config error: %v\n", err)
		return ExitConfigOrArg
	}
	if len(cfg.Names) == 0 {
		fmt.Println("No registered names in config.toml.")
		return 0
	}

	slugs := make([]string, 0, len(cfg.Names))
	for k := range cfg.Names {
		slugs = append(slugs, k)
	}
	sort.Strings(slugs)

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tTYPE\tDESCRIPTION\tSOPS_RECIPIENT")
	for _, s := range slugs {
		e := cfg.Names[s]
		kind := "direct"
		rec := "-"
		if e.IsSops() {
			kind = "sops"
			rec = e.SopsRecipient
		}
		desc := e.Description
		if desc == "" {
			desc = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s, kind, desc, rec)
	}
	_ = tw.Flush()
	return 0
}

func runNameSet(args []string) int {
	fs := pflag.NewFlagSet("name set", pflag.ContinueOnError)
	var desc string
	fs.StringVar(&desc, "desc", "", "Updated description for the existing registered name")
	if err := fs.Parse(args); err != nil {
		if err == pflag.ErrHelp {
			return 0
		}
		fmt.Fprintf(os.Stderr, "[outsider] Argument error: %v\n", err)
		return ExitConfigOrArg
	}
	pos := fs.Args()
	if len(pos) != 1 || strings.TrimSpace(pos[0]) == "" {
		fmt.Fprintln(os.Stderr, "[outsider] Usage: outsider name set <NAME> --desc TEXT")
		return ExitConfigOrArg
	}
	if !fs.Changed("desc") {
		fmt.Fprintln(os.Stderr, "[outsider] Argument error: --desc is required")
		return ExitConfigOrArg
	}

	slug := proto.SlugifyName(pos[0])
	rawCfg, err := LoadRawConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Config error: %v\n", err)
		return ExitConfigOrArg
	}
	entry, exists := rawCfg.Names[slug]
	if !exists {
		fmt.Fprintf(os.Stderr, "[outsider] Error: name %q is not registered (use `outsider name add` to enroll via approval)\n", slug)
		return ExitConfigOrArg
	}
	entry.Description = strings.TrimSpace(desc)
	rawCfg.Names[slug] = entry
	if _, err := SaveConfig(rawCfg); err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Config error: %v\n", err)
		return ExitConfigOrArg
	}
	fmt.Printf("Updated %s (description = %q)\n", slug, entry.Description)
	return 0
}

func runNameRM(args []string) int {
	fs := pflag.NewFlagSet("name rm", pflag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		if err == pflag.ErrHelp {
			return 0
		}
		fmt.Fprintf(os.Stderr, "[outsider] Argument error: %v\n", err)
		return ExitConfigOrArg
	}
	pos := fs.Args()
	if len(pos) != 1 || strings.TrimSpace(pos[0]) == "" {
		fmt.Fprintln(os.Stderr, "[outsider] Usage: outsider name rm <NAME>")
		return ExitConfigOrArg
	}

	slug := proto.SlugifyName(pos[0])
	rawCfg, err := LoadRawConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Config error: %v\n", err)
		return ExitConfigOrArg
	}
	if _, exists := rawCfg.Names[slug]; !exists {
		fmt.Fprintf(os.Stderr, "[outsider] Error: name %q is not registered\n", slug)
		return ExitConfigOrArg
	}
	delete(rawCfg.Names, slug)
	if _, err := SaveConfig(rawCfg); err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Config error: %v\n", err)
		return ExitConfigOrArg
	}
	fmt.Printf("Removed %s from config.toml\n", slug)
	return 0
}

func saveDirectNameIfAbsent(slug, desc string) error {
	rawCfg, err := LoadRawConfig()
	if err != nil {
		return err
	}
	if existing, ok := rawCfg.Names[slug]; ok {
		if existing.IsSops() {
			return fmt.Errorf("name %q is already registered as a SOPS age key", slug)
		}
		return nil
	}
	rawCfg.Names[slug] = NameEntry{Description: strings.TrimSpace(desc)}
	_, err = SaveConfig(rawCfg)
	return err
}

func saveSopsName(slug, recipient, desc string, updateDesc bool) error {
	rawCfg, err := LoadRawConfig()
	if err != nil {
		return errConfig("Config error: %v", err)
	}
	if err := rawCfg.CheckRecipientUnique(slug, recipient); err != nil {
		return errConfig("%v", err)
	}
	if existing, ok := rawCfg.Names[slug]; ok {
		if !existing.IsSops() {
			return errConfig("name %q is already registered as a Direct secret", slug)
		}
		if strings.TrimSpace(existing.SopsRecipient) != recipient {
			return errCrypto("approved age key public key %s does not match registered sops_recipient %s for name %q", recipient, existing.SopsRecipient, slug)
		}
		if updateDesc {
			existing.Description = strings.TrimSpace(desc)
			rawCfg.Names[slug] = existing
			if _, err := SaveConfig(rawCfg); err != nil {
				return errConfig("Config error: %v", err)
			}
		}
		return nil
	}

	entry := NameEntry{SopsRecipient: recipient}
	if updateDesc {
		entry.Description = strings.TrimSpace(desc)
	}
	rawCfg.Names[slug] = entry
	if _, err := SaveConfig(rawCfg); err != nil {
		return errConfig("Config error: %v", err)
	}
	return nil
}
