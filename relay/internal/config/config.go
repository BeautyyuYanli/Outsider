package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config defines the static relay.toml configuration.
type Config struct {
	PublicBaseURL              string           `toml:"public_base_url"`
	ListenAddr                 string           `toml:"listen_addr"`
	RedactNotificationMetadata bool             `toml:"redact_notification_metadata"`
	DefaultTTLSecs             int              `toml:"default_ttl_secs"`
	MaxTTLSecs                 int              `toml:"max_ttl_secs"`
	GraceTTLSecs               int              `toml:"grace_ttl_secs"`
	MaxPendingPerClient        int              `toml:"max_pending_per_client"`
	RateLimitPerMin            int              `toml:"rate_limit_per_min"`
	Notifiers                  []NotifierConfig `toml:"notifiers"`
	TrustedClients             []TrustedClient  `toml:"trusted_clients"`

	clientByKey map[string]TrustedClient
}

// NotifierConfig describes a single notification destination.
type NotifierConfig struct {
	Type         string            `toml:"type"`
	URL          string            `toml:"url"`
	Method       string            `toml:"method"`
	Headers      map[string]string `toml:"headers"`
	BodyTemplate string            `toml:"body_template"`
}

// TrustedClient maps a requester's Ed25519 public key to a human-readable device name.
type TrustedClient struct {
	Name      string `toml:"name"`
	PublicKey string `toml:"public_key"`
}

// LoadFile reads and validates relay.toml, applying OUTSIDER_RELAY_* environment overrides.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	return Parse(data)
}

// Parse parses TOML bytes, applies defaults and env overrides, and validates invariants.
func Parse(data []byte) (*Config, error) {
	cfg := &Config{
		ListenAddr:          "127.0.0.1:8080",
		DefaultTTLSecs:      120,
		MaxTTLSecs:          300,
		GraceTTLSecs:        30,
		MaxPendingPerClient: 3,
		RateLimitPerMin:     10,
	}
	if _, err := toml.Decode(string(data), cfg); err != nil {
		return nil, fmt.Errorf("parse toml: %w", err)
	}
	if err := applyEnvOverrides(cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyEnvOverrides(cfg *Config) error {
	if v := strings.TrimSpace(os.Getenv("OUTSIDER_RELAY_PUBLIC_BASE_URL")); v != "" {
		cfg.PublicBaseURL = v
	}
	if v := strings.TrimSpace(os.Getenv("OUTSIDER_RELAY_LISTEN_ADDR")); v != "" {
		cfg.ListenAddr = v
	}
	if v := strings.TrimSpace(os.Getenv("OUTSIDER_RELAY_REDACT_NOTIFICATION_METADATA")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("invalid OUTSIDER_RELAY_REDACT_NOTIFICATION_METADATA: %w", err)
		}
		cfg.RedactNotificationMetadata = b
	}
	intOverrides := []struct {
		env string
		dst *int
	}{
		{"OUTSIDER_RELAY_DEFAULT_TTL_SECS", &cfg.DefaultTTLSecs},
		{"OUTSIDER_RELAY_MAX_TTL_SECS", &cfg.MaxTTLSecs},
		{"OUTSIDER_RELAY_GRACE_TTL_SECS", &cfg.GraceTTLSecs},
		{"OUTSIDER_RELAY_MAX_PENDING_PER_CLIENT", &cfg.MaxPendingPerClient},
		{"OUTSIDER_RELAY_RATE_LIMIT_PER_MIN", &cfg.RateLimitPerMin},
	}
	for _, o := range intOverrides {
		if v := strings.TrimSpace(os.Getenv(o.env)); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("invalid %s: %w", o.env, err)
			}
			*o.dst = n
		}
	}
	return nil
}

// Validate normalizes fields and ensures the configuration is safe to run.
func (c *Config) Validate() error {
	c.PublicBaseURL = strings.TrimRight(strings.TrimSpace(c.PublicBaseURL), "/")
	if c.PublicBaseURL == "" {
		return errors.New("public_base_url is required")
	}
	u, err := url.Parse(c.PublicBaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("public_base_url must be a valid http(s) URL: %q", c.PublicBaseURL)
	}
	if strings.TrimSpace(c.ListenAddr) == "" {
		return errors.New("listen_addr cannot be empty")
	}
	if c.DefaultTTLSecs <= 0 || c.MaxTTLSecs <= 0 || c.DefaultTTLSecs > c.MaxTTLSecs {
		return fmt.Errorf("invalid ttl bounds: default=%d max=%d", c.DefaultTTLSecs, c.MaxTTLSecs)
	}
	if c.GraceTTLSecs <= 0 {
		return fmt.Errorf("grace_ttl_secs must be positive, got %d", c.GraceTTLSecs)
	}
	if c.MaxPendingPerClient <= 0 {
		return fmt.Errorf("max_pending_per_client must be positive, got %d", c.MaxPendingPerClient)
	}
	if c.RateLimitPerMin <= 0 {
		return fmt.Errorf("rate_limit_per_min must be positive, got %d", c.RateLimitPerMin)
	}

	c.clientByKey = make(map[string]TrustedClient, len(c.TrustedClients))
	seenNames := make(map[string]struct{}, len(c.TrustedClients))
	for i, tc := range c.TrustedClients {
		name := strings.TrimSpace(tc.Name)
		pk := strings.TrimSpace(tc.PublicKey)
		if name == "" {
			return fmt.Errorf("trusted_clients[%d].name is required", i)
		}
		raw, err := base64.RawURLEncoding.DecodeString(pk)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("trusted_clients[%d].public_key must be base64url-encoded 32-byte Ed25519 public key", i)
		}
		if _, dup := c.clientByKey[pk]; dup {
			return fmt.Errorf("duplicate trusted_clients public_key for %q", name)
		}
		if _, dupName := seenNames[name]; dupName {
			return fmt.Errorf("duplicate trusted_clients name %q", name)
		}
		seenNames[name] = struct{}{}
		c.clientByKey[pk] = TrustedClient{Name: name, PublicKey: pk}
	}

	for i, n := range c.Notifiers {
		switch strings.ToLower(strings.TrimSpace(n.Type)) {
		case "shoutrrr":
			if strings.TrimSpace(n.URL) == "" {
				return fmt.Errorf("notifiers[%d].url is required for shoutrrr", i)
			}
		case "webhook":
			if strings.TrimSpace(n.URL) == "" {
				return fmt.Errorf("notifiers[%d].url is required for webhook", i)
			}
			wu, err := url.Parse(n.URL)
			if err != nil || (wu.Scheme != "http" && wu.Scheme != "https") || wu.Host == "" {
				return fmt.Errorf("notifiers[%d].url must be a valid http(s) URL", i)
			}
		default:
			return fmt.Errorf("notifiers[%d].type must be \"shoutrrr\" or \"webhook\", got %q", i, n.Type)
		}
	}

	return nil
}

// LookupClient finds a trusted client by its Base64URL Ed25519 public key.
func (c *Config) LookupClient(idPkB64u string) (TrustedClient, bool) {
	tc, ok := c.clientByKey[idPkB64u]
	return tc, ok
}
