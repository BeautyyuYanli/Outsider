package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"outsider/internal/proto"
)

func printRelaySnippet(deviceName string, id *proto.IdentityKey) {
	fp := id.Fingerprint()
	pk := id.PublicKeyB64u()
	fmt.Printf("Device Name : %s\n", deviceName)
	fmt.Printf("Device FP   : %s\n", fp)
	fmt.Printf("Public Key  : %s\n", pk)
	fmt.Println()
	fmt.Println("# Paste into relay.toml:")
	fmt.Println("[[trusted_clients]]")
	fmt.Printf("name = %q\n", deviceName)
	fmt.Printf("public_key = %q\n", pk)
}

func runInit(args []string) int {
	fs := pflag.NewFlagSet("init", pflag.ContinueOnError)
	var relayURL, deviceName string
	var force bool
	fs.StringVar(&relayURL, "relay", "", "Relay base URL (e.g. https://relay.example.com)")
	fs.StringVar(&deviceName, "name", "", "Human-readable device name for relay.toml & approval page")
	fs.BoolVar(&force, "force", false, "Overwrite existing identity key and config")
	if err := fs.Parse(args); err != nil {
		if err == pflag.ErrHelp {
			return 0
		}
		fmt.Fprintf(os.Stderr, "[outsider] Error: %v\n", err)
		return ExitConfigOrArg
	}

	relayURL = strings.TrimRight(strings.TrimSpace(relayURL), "/")
	deviceName = strings.TrimSpace(deviceName)
	if relayURL == "" || (!strings.HasPrefix(relayURL, "http://") && !strings.HasPrefix(relayURL, "https://")) {
		fmt.Fprintln(os.Stderr, "[outsider] Error: --relay must be an http(s):// URL")
		return ExitConfigOrArg
	}
	if deviceName == "" {
		fmt.Fprintln(os.Stderr, "[outsider] Error: --name cannot be empty")
		return ExitConfigOrArg
	}

	keyPath, err := DefaultIdentityKeyPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Error: %v\n", err)
		return ExitConfigOrArg
	}
	if _, err := os.Stat(keyPath); err == nil && !force {
		fmt.Fprintf(os.Stderr, "[outsider] Error: identity key already exists at %s (use --force to overwrite)\n", keyPath)
		return ExitConfigOrArg
	}

	id, err := proto.GenerateIdentityKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Error: %v\n", err)
		return ExitConfigOrArg
	}
	defer id.Wipe()

	if err := SaveIdentityKey(keyPath, id); err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Error: %v\n", err)
		return ExitConfigOrArg
	}

	cfg := &ClientConfig{
		RelayURL:           relayURL,
		DeviceName:         deviceName,
		IdentityKeyPath:    keyPath,
		DefaultTimeoutSecs: 120,
	}
	cfgPath, err := SaveConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Error: %v\n", err)
		return ExitConfigOrArg
	}

	fmt.Fprintf(os.Stderr, "[outsider] Saved config: %s\n", cfgPath)
	fmt.Fprintf(os.Stderr, "[outsider] Saved identity key (0600): %s\n", keyPath)
	printRelaySnippet(deviceName, id)
	return 0
}

func runID(args []string) int {
	fs := pflag.NewFlagSet("id", pflag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		if err == pflag.ErrHelp {
			return 0
		}
		fmt.Fprintf(os.Stderr, "[outsider] Error: %v\n", err)
		return ExitConfigOrArg
	}
	cfg, id, err := loadConfigAndIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
		return exitCodeOf(err)
	}
	defer id.Wipe()

	printRelaySnippet(cfg.DeviceName, id)
	return 0
}

func runDoctor(args []string) int {
	fs := pflag.NewFlagSet("doctor", pflag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		if err == pflag.ErrHelp {
			return 0
		}
		fmt.Fprintf(os.Stderr, "[outsider] Error: %v\n", err)
		return ExitConfigOrArg
	}

	cfg, id, err := loadConfigAndIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
		return exitCodeOf(err)
	}
	defer id.Wipe()

	fmt.Printf("Config      : OK (%s)\n", cfg.RelayURL)
	fmt.Printf("Identity    : OK (FP: %s)\n", id.Fingerprint())

	client := NewRelayClient(cfg.RelayURL)
	ctx := context.Background()
	if err := client.Healthz(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Relay /healthz failed: %v\n", err)
		return exitCodeOf(err)
	}
	fmt.Println("Relay Health: OK")

	res, err := client.Doctor(ctx, id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Relay auth check failed: %v\n", err)
		return exitCodeOf(err)
	}
	if !res.OK {
		fmt.Fprintln(os.Stderr, "[outsider] Relay auth returned not ok")
		return ExitRelayOrAuth
	}
	fmt.Printf("Relay Auth  : OK (trusted as %q)\n", res.ClientName)
	return 0
}
