package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"outsider/internal/proto"
	relaycfg "outsider/internal/relay/config"
	"outsider/internal/relay/notifier"
	"outsider/internal/relay/server"
	"outsider/internal/relay/session"
	"outsider/internal/sopsage"
)

type autoApprover struct {
	mu       sync.Mutex
	relayURL string
	queue    []string
	commands []string
	t        *testing.T
}

func (a *autoApprover) enqueue(secrets ...string) {
	a.mu.Lock()
	a.queue = append(a.queue, secrets...)
	a.mu.Unlock()
}

func (a *autoApprover) seenCommands() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, len(a.commands))
	copy(out, a.commands)
	return out
}

func (a *autoApprover) NotifyRequest(_ context.Context, p notifier.NotifyPayload) error {
	a.mu.Lock()
	a.commands = append(a.commands, p.Command)
	if len(a.queue) == 0 {
		a.mu.Unlock()
		return nil
	}
	secret := a.queue[0]
	a.queue = a.queue[1:]
	a.mu.Unlock()

	// Extract approve_token from URL ".../approve/<slug>/<token>".
	parts := strings.Split(p.URL, "/")
	token := parts[len(parts)-1]

	go func() {
		resp, err := http.Get(a.relayURL + "/v1/approve/" + token)
		if err != nil {
			a.t.Errorf("GET /v1/approve: %v", err)
			return
		}
		var snap session.SessionSnapshot
		_ = json.NewDecoder(resp.Body).Decode(&snap)
		resp.Body.Close()

		pkReq, _ := base64.RawURLEncoding.DecodeString(snap.PkReq)
		ctxHash := proto.ComputeContextHash(snap.Context)
		env, err := proto.EncryptEnvelope([]byte(secret), snap.SessionID, pkReq, ctxHash[:], nil, nil)
		if err != nil {
			a.t.Errorf("EncryptEnvelope: %v", err)
			return
		}
		body, _ := json.Marshal(env)
		postResp, err := http.Post(a.relayURL+"/v1/approve/"+token, "application/json", bytes.NewReader(body))
		if err != nil {
			a.t.Errorf("POST /v1/approve: %v", err)
			return
		}
		postResp.Body.Close()
	}()
	return nil
}

func setupTestRelayAndClient(t *testing.T) (*autoApprover, string, func()) {
	t.Helper()
	allowExecReplace = false

	cfgDir := t.TempDir()
	t.Setenv("OUTSIDER_CONFIG_DIR", cfgDir)

	// Initialize identity key first with dummy relay URL, then wire relay to trust this key.
	if code := Run([]string{"init", "--relay", "http://127.0.0.1:1", "--name", "test-box"}); code != 0 {
		t.Fatalf("outsider init exited %d", code)
	}
	_, id, err := loadConfigAndIdentity()
	if err != nil {
		t.Fatalf("loadConfigAndIdentity: %v", err)
	}
	pubB64 := id.PublicKeyB64u()
	id.Wipe()

	approver := &autoApprover{t: t}
	store := session.NewStore()
	var ts *httptest.Server
	cfgTOML := `
public_base_url = "http://placeholder.local"
max_pending_per_client = 5
rate_limit_per_min = 60

[[trusted_clients]]
name = "test-box"
public_key = "` + pubB64 + `"
`
	rcfg, err := relaycfg.Parse([]byte(cfgTOML))
	if err != nil {
		t.Fatalf("relay config parse: %v", err)
	}
	srv := server.New(rcfg, store, approver, nil)
	ts = httptest.NewServer(srv.Handler())
	approver.relayURL = ts.URL

	// Update config.toml relay_url + inject legacy default_redact = true to test backwards compatibility.
	cfgPath := filepath.Join(cfgDir, "config.toml")
	rawCfgBytes, _ := os.ReadFile(cfgPath)
	updated := strings.Replace(string(rawCfgBytes), "http://127.0.0.1:1", ts.URL, 1) + "\ndefault_redact = true\n"
	if err := os.WriteFile(cfgPath, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}

	return approver, cfgDir, func() {
		ts.Close()
	}
}

func TestDoctorAndNameCRUDAndSopsWorkflow(t *testing.T) {
	approver, cfgDir, cleanup := setupTestRelayAndClient(t)
	defer cleanup()

	// 1. Doctor succeeds even with legacy default_redact in config.toml.
	if code := Run([]string{"doctor"}); code != 0 {
		t.Fatalf("doctor exited %d", code)
	}

	// 2. `name set` on non-existent name must fail (cannot create locally).
	if code := Run([]string{"name", "set", "ghost", "--desc", "nope"}); code != ExitConfigOrArg {
		t.Fatalf("name set on unknown name = %d, want 100", code)
	}

	// 3. `name add` Direct secret via real approval.
	approver.enqueue("direct-db-pass")
	if code := Run([]string{"name", "add", "Prod DB", "--desc", "Production DB password"}); code != 0 {
		t.Fatalf("name add direct exited %d", code)
	}
	// Duplicate `name add` must fail 100.
	if code := Run([]string{"name", "add", "prod-db"}); code != ExitConfigOrArg {
		t.Fatalf("duplicate name add = %d, want 100", code)
	}
	// `name set` updates description only.
	if code := Run([]string{"name", "set", "prod-db", "--desc", "Updated DB desc"}); code != 0 {
		t.Fatalf("name set exited %d", code)
	}
	cfg, err := LoadRawConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Names["prod-db"].Description != "Updated DB desc" || cfg.Names["prod-db"].IsSops() {
		t.Fatalf("unexpected prod-db entry: %+v", cfg.Names["prod-db"])
	}

	// 4. `sops init` first file -> 1 approval, creates file & registers [names.personal-sops] with empty desc.
	ageID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	file1 := filepath.Join(t.TempDir(), "one.enc.yaml")
	file2 := filepath.Join(t.TempDir(), "two.enc.yaml")

	approver.enqueue(ageID.String())
	if code := Run([]string{"sops", "init", file1, "--name", "personal-sops"}); code != 0 {
		t.Fatalf("sops init file1 exited %d", code)
	}
	cfg, _ = LoadRawConfig()
	if e := cfg.Names["personal-sops"]; e.SopsRecipient != ageID.Recipient().String() || e.Description != "" {
		t.Fatalf("unexpected personal-sops entry after init: %+v", e)
	}

	// Verify duplicate sops_recipient via `name add --sops` is rejected (uniqueness invariant).
	approver.enqueue(ageID.String())
	if code := Run([]string{"name", "add", "dup-sops", "--sops"}); code != ExitConfigOrArg {
		t.Fatalf("duplicate sops_recipient should exit 100, got %d", code)
	}

	// 5. `sops init` second file with SAME registered name -> 0 approvals!
	beforeCount := len(approver.seenCommands())
	if code := Run([]string{"sops", "init", file2, "--name", "personal-sops"}); code != 0 {
		t.Fatalf("sops init file2 (0-approval reuse) exited %d", code)
	}
	if len(approver.seenCommands()) != beforeCount {
		t.Fatalf("sops init file2 triggered unexpected approval! commands=%v", approver.seenCommands())
	}

	// 6. `sops set` multi-key: verifies reversed order (new values FIRST, SOPS_AGE_KEY LAST!).
	approver.enqueue("ghp_token_xyz", "db_pass_999", ageID.String())
	if code := Run([]string{"sops", "set", file1, "GH_TOKEN", "db.password"}); code != 0 {
		t.Fatalf("sops set multi-key exited %d", code)
	}
	cmds := approver.seenCommands()
	last3 := cmds[len(cmds)-3:]
	if !strings.HasPrefix(last3[0], "[sops:set-value ") ||
		!strings.HasPrefix(last3[1], "[sops:set-value ") ||
		!strings.HasPrefix(last3[2], "[sops:set ") {
		t.Fatalf("expected value approvals BEFORE SOPS_AGE_KEY approval, got %v", last3)
	}

	// 7. Fail-Fast: dotted key with `--env-all` must exit 100 BEFORE calling Relay!
	beforeCount = len(approver.seenCommands())
	if code := Run([]string{"run", "--sops", file1, "--env-all", "--", "true"}); code != ExitConfigOrArg {
		t.Fatalf("run --sops with dotted key and --env-all should fail-fast 100, got %d", code)
	}
	if len(approver.seenCommands()) != beforeCount {
		t.Fatalf("fail-fast should not have contacted relay")
	}

	// 8. `outsider run --sops` auto-resolves `--name personal-sops`, injects GH_TOKEN, and does NOT expose SOPS_AGE_KEY.
	outMarker := filepath.Join(t.TempDir(), "marker.txt")
	approver.enqueue(ageID.String())
	code := Run([]string{
		"run", "--sops", file1, "--sops-key", "GH_TOKEN", "--env-all", "--",
		"sh", "-c", `printf "%s|%s" "$GH_TOKEN" "${SOPS_AGE_KEY:-UNSET}" > "` + outMarker + `"`,
	})
	if code != 0 {
		t.Fatalf("run --sops --env-all exited %d", code)
	}
	gotMarker, _ := os.ReadFile(outMarker)
	if string(gotMarker) != "ghp_token_xyz|UNSET" {
		t.Fatalf("child saw %q, want %q", string(gotMarker), "ghp_token_xyz|UNSET")
	}

	// 9. Multi-key `--file --file-format json` handoff & verify temp file is deleted after exit.
	jsonOut := filepath.Join(t.TempDir(), "captured.json")
	pathRecord := filepath.Join(t.TempDir(), "secret_path.txt")
	approver.enqueue(ageID.String())
	code = Run([]string{
		"run", "--sops", file1, "--file", "--file-format", "json", "--",
		"sh", "-c", `cp "{{file}}" "` + jsonOut + `" && printf "%s" "{{file}}" > "` + pathRecord + `"`,
	})
	if code != 0 {
		t.Fatalf("run --sops --file --file-format json exited %d", code)
	}
	rawJSON, _ := os.ReadFile(jsonOut)
	if !strings.Contains(string(rawJSON), `"GH_TOKEN": "ghp_token_xyz"`) || !strings.Contains(string(rawJSON), `"password": "db_pass_999"`) {
		t.Fatalf("unexpected json handoff file:\n%s", string(rawJSON))
	}
	secretTempPath, _ := os.ReadFile(pathRecord)
	if _, err := os.Stat(string(secretTempPath)); !os.IsNotExist(err) {
		t.Fatalf("temp secret file %s was not removed after child exit", string(secretTempPath))
	}

	// 10. Direct `run` without `--save-name` must NOT mutate config.toml; with `--save-name` it DOES.
	approver.enqueue("ephemeral-secret")
	if code := Run([]string{"run", "--name", "temp-only", "--env", "TOK", "--", "true"}); code != 0 {
		t.Fatalf("direct run without --save-name exited %d", code)
	}
	cfg, _ = LoadRawConfig()
	if _, exists := cfg.Names["temp-only"]; exists {
		t.Fatalf("run without --save-name polluted config.toml")
	}

	approver.enqueue("saved-secret")
	if code := Run([]string{"run", "--name", "saved-direct", "--reason", "Deploy key", "--save-name", "--env", "TOK", "--", "true"}); code != 0 {
		t.Fatalf("direct run with --save-name exited %d", code)
	}
	cfg, _ = LoadRawConfig()
	if e, exists := cfg.Names["saved-direct"]; !exists || e.Description != "Deploy key" {
		t.Fatalf("expected saved-direct in config.toml, got %+v", cfg.Names)
	}

	// 11. `sops unset` multi-key.
	approver.enqueue(ageID.String())
	if code := Run([]string{"sops", "unset", file1, "GH_TOKEN", "db.password"}); code != 0 {
		t.Fatalf("sops unset exited %d", code)
	}
	meta, err := sopsage.InspectFile(file1)
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Keys) != 0 {
		t.Fatalf("expected 0 keys after unset, got %+v", meta.Keys)
	}

	// 12. `name rm` removes entry cleanly.
	if code := Run([]string{"name", "rm", "saved-direct"}); code != 0 {
		t.Fatalf("name rm exited %d", code)
	}
	cfg, _ = LoadRawConfig()
	if _, exists := cfg.Names["saved-direct"]; exists {
		t.Fatalf("saved-direct should have been removed")
	}

	// Verify config.toml permissions remain 0600.
	info, err := os.Stat(filepath.Join(cfgDir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config.toml mode = %04o, want 0600", info.Mode().Perm())
	}
	_ = time.Second
}
