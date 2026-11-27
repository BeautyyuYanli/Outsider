package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"outsider/internal/proto"
)

// NameEntry represents a verified approval name stored in config.toml under [names.<slug>].
type NameEntry struct {
	Description   string `toml:"description,omitempty"`
	SopsRecipient string `toml:"sops_recipient,omitempty"`
}

// IsSops reports whether this name represents a SOPS age key rather than a Direct secret.
func (n NameEntry) IsSops() bool {
	return strings.TrimSpace(n.SopsRecipient) != ""
}

// ClientConfig is persisted at ~/.config/outsider/config.toml.
type ClientConfig struct {
	RelayURL           string               `toml:"relay_url"`
	DeviceName         string               `toml:"device_name"`
	IdentityKeyPath    string               `toml:"identity_key_path"`
	DefaultTimeoutSecs uint32               `toml:"default_timeout_secs"`
	Names              map[string]NameEntry `toml:"names,omitempty"`
}

// ConfigDir resolves the outsider configuration directory.
func ConfigDir() (string, error) {
	if dir := strings.TrimSpace(os.Getenv("OUTSIDER_CONFIG_DIR")); dir != "" {
		return dir, nil
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		return filepath.Join(xdg, "outsider"), nil
	}
	home := os.Getenv("HOME")
	if home == "" {
		home = os.Getenv("USERPROFILE")
	}
	if home == "" {
		return "", fmt.Errorf("cannot determine home directory (HOME/USERPROFILE unset)")
	}
	return filepath.Join(home, ".config", "outsider"), nil
}

// ConfigFilePath returns ~/.config/outsider/config.toml.
func ConfigFilePath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.toml"), nil
}

// DefaultIdentityKeyPath returns ~/.config/outsider/identity.key.
func DefaultIdentityKeyPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "identity.key"), nil
}

// ExpandTilde expands a leading "~/" to the user's home directory.
func ExpandTilde(p string) (string, error) {
	if strings.HasPrefix(p, "~/") {
		home := os.Getenv("HOME")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		if home == "" {
			return "", fmt.Errorf("cannot expand ~: HOME unset")
		}
		return filepath.Join(home, p[2:]), nil
	}
	return p, nil
}

// LoadRawConfig reads config.toml from disk without applying runtime environment overrides.
// Use this when mutating and saving config.toml (e.g. updating [names.*]).
func LoadRawConfig() (*ClientConfig, error) {
	path, err := ConfigFilePath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w (run `outsider init` first)", path, err)
	}
	cfg := &ClientConfig{
		DeviceName:         "outsider-client",
		DefaultTimeoutSecs: 120,
	}
	// BurntSushi/toml ignores unknown legacy keys such as default_redact by default.
	if _, err := toml.Decode(string(raw), cfg); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	if cfg.DefaultTimeoutSecs == 0 {
		cfg.DefaultTimeoutSecs = 120
	}
	if cfg.Names == nil {
		cfg.Names = make(map[string]NameEntry)
	}
	cfg.RelayURL = strings.TrimRight(strings.TrimSpace(cfg.RelayURL), "/")
	return cfg, nil
}

// LoadConfig loads config.toml and applies runtime OUTSIDER_RELAY_URL / OUTSIDER_IDENTITY_KEY overrides.
func LoadConfig() (*ClientConfig, error) {
	cfg, err := LoadRawConfig()
	if err != nil {
		return nil, err
	}
	if u := strings.TrimSpace(os.Getenv("OUTSIDER_RELAY_URL")); u != "" {
		cfg.RelayURL = u
	}
	if kp := strings.TrimSpace(os.Getenv("OUTSIDER_IDENTITY_KEY")); kp != "" {
		cfg.IdentityKeyPath = kp
	}
	cfg.RelayURL = strings.TrimRight(strings.TrimSpace(cfg.RelayURL), "/")
	if cfg.RelayURL == "" {
		return nil, fmt.Errorf("relay_url is empty")
	}
	return cfg, nil
}

// SaveConfig atomically writes config.toml with 0600 permissions inside a 0700 directory.
func SaveConfig(cfg *ClientConfig) (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	if err := ensurePrivateDir(dir); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "config.toml")

	// Avoid writing an empty [names] header if there are no entries.
	toWrite := *cfg
	if len(toWrite.Names) == 0 {
		toWrite.Names = nil
	}

	var buf bytes.Buffer
	enc := toml.NewEncoder(&buf)
	if err := enc.Encode(&toWrite); err != nil {
		return "", fmt.Errorf("serialize config: %w", err)
	}

	if err := writeFileAtomic(path, buf.Bytes(), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
}

// CheckRecipientUnique ensures recipient is not already bound to another slug in cfg.Names.
func (c *ClientConfig) CheckRecipientUnique(slug, recipient string) error {
	recipient = strings.TrimSpace(recipient)
	if recipient == "" {
		return nil
	}
	for otherSlug, entry := range c.Names {
		if otherSlug == slug {
			continue
		}
		if strings.TrimSpace(entry.SopsRecipient) == recipient {
			return fmt.Errorf(
				"age recipient %s is already bound to name %q (use --name %s or remove it with `outsider name rm %s`)",
				recipient, otherSlug, otherSlug, otherSlug,
			)
		}
	}
	return nil
}

// ResolveSopsName matches a SOPS file's age recipients against [names.*].sops_recipient.
func (c *ClientConfig) ResolveSopsName(recipients []string) (string, error) {
	recSet := make(map[string]bool, len(recipients))
	for _, r := range recipients {
		recSet[strings.TrimSpace(r)] = true
	}
	var matches []string
	for slug, entry := range c.Names {
		r := strings.TrimSpace(entry.SopsRecipient)
		if r != "" && recSet[r] {
			matches = append(matches, slug)
		}
	}
	sort.Strings(matches)
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf(
			"no registered SOPS name in config.toml matches this file's age recipient(s); " +
				"pass `--name <slug>` explicitly or enroll the key with `outsider name add <slug> --sops`",
		)
	default:
		return "", fmt.Errorf(
			"multiple registered SOPS names match this file (%s); specify `--name <slug>` explicitly",
			strings.Join(matches, ", "),
		)
	}
}

// SaveIdentityKey writes the base64url Ed25519 seed to path with strict 0600 permissions.
func SaveIdentityKey(path string, key *proto.IdentityKey) error {
	if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	encoded := key.SeedB64u()
	defer clear(encoded)
	data := make([]byte, len(encoded)+1)
	copy(data, encoded)
	data[len(encoded)] = '\n'
	defer clear(data)

	return writeFileAtomic(path, data, 0o600)
}

// LoadIdentityKey validates file permissions (on Unix) and loads the Ed25519 IdentityKey.
func LoadIdentityKey(path string) (*proto.IdentityKey, error) {
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat identity key %s: %w", path, err)
		}
		mode := info.Mode().Perm()
		if mode&0o077 != 0 {
			return nil, fmt.Errorf(
				"identity key %s has insecure permissions %04o; run `chmod 600 %s`",
				path, mode, path,
			)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity key %s: %w", path, err)
	}
	defer clear(raw)
	return proto.IdentityKeyFromB64u(string(raw))
}

func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("chmod 0700 %s: %w", dir, err)
		}
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".outsider-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if runtime.GOOS != "windows" {
		if err := tmp.Chmod(perm); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// loadConfigAndIdentity is a shared helper for commands that need both config and identity key.
func loadConfigAndIdentity() (*ClientConfig, *proto.IdentityKey, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, nil, errConfig("Config error: %v", err)
	}
	keyPath, err := ExpandTilde(cfg.IdentityKeyPath)
	if err != nil {
		return nil, nil, errConfig("Config error: %v", err)
	}
	id, err := LoadIdentityKey(keyPath)
	if err != nil {
		return nil, nil, errConfig("Identity key error: %v", err)
	}
	return cfg, id, nil
}
