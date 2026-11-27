package sopsage

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestInitSetUnsetDecryptRoundTrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ageKey := []byte("# created: test\n# public key: " + id.Recipient().String() + "\n" + id.String() + "\n")
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.enc.yaml")

	// 1. Init empty SOPS file.
	if err := InitFile(path, []string{id.Recipient().String()}); err != nil {
		t.Fatalf("InitFile: %v", err)
	}
	if err := InitFile(path, []string{id.Recipient().String()}); err == nil {
		t.Fatalf("InitFile should fail if file exists")
	}

	meta, err := InspectFile(path)
	if err != nil {
		t.Fatalf("InspectFile: %v", err)
	}
	if len(meta.Recipients) != 1 || meta.Recipients[0] != id.Recipient().String() {
		t.Fatalf("unexpected recipients: %v", meta.Recipients)
	}
	if len(meta.Keys) != 0 {
		t.Fatalf("expected 0 keys after init, got %d", len(meta.Keys))
	}

	// Verify empty file decrypts cleanly.
	kvs, err := Decrypt(path, ageKey, nil)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if len(kvs) != 0 {
		t.Fatalf("expected 0 decrypted keys, got %d", len(kvs))
	}

	// 2. Set top-level and nested keys in one call.
	err = SetKeys(path, ageKey, []KV{
		{Key: "GH_TOKEN", Value: []byte("ghp_secret_123")},
		{Key: "MULTILINE", Value: []byte("line1\nline2\n")},
		{Key: "db.password", Value: []byte("p@ss word!")},
	})
	if err != nil {
		t.Fatalf("SetKeys: %v", err)
	}

	// Capture ciphertext of GH_TOKEN before updating db.password to verify untouched fields keep original IV.
	rawBefore, _ := os.ReadFile(path)
	var ghLineBefore string
	for _, line := range strings.Split(string(rawBefore), "\n") {
		if strings.Contains(line, "GH_TOKEN:") {
			ghLineBefore = line
		}
	}

	if err := SetKeys(path, ageKey, []KV{{Key: "db.password", Value: []byte("new_pass")}}); err != nil {
		t.Fatalf("SetKeys update: %v", err)
	}
	rawAfter, _ := os.ReadFile(path)
	if !strings.Contains(string(rawAfter), ghLineBefore) {
		t.Fatalf("untouched GH_TOKEN ciphertext changed across SetKeys update")
	}

	// Inspect keys locally without private key.
	meta, err = InspectFile(path)
	if err != nil {
		t.Fatalf("InspectFile after set: %v", err)
	}
	if !meta.KeySet["GH_TOKEN"] || !meta.KeySet["MULTILINE"] || !meta.KeySet["db.password"] {
		t.Fatalf("unexpected keys after set: %+v", meta.Keys)
	}

	// Decrypt selected key.
	got, err := Decrypt(path, ageKey, []string{"db.password", "GH_TOKEN"})
	if err != nil {
		t.Fatalf("Decrypt selected: %v", err)
	}
	defer WipeKVs(got)
	if len(got) != 2 || string(got[0].Value) != "new_pass" || string(got[1].Value) != "ghp_secret_123" {
		t.Fatalf("unexpected decrypted values: %+v", got)
	}

	// Wrong age key must fail with ErrDecrypt.
	wrongID, _ := age.GenerateX25519Identity()
	if _, err := Decrypt(path, []byte(wrongID.String()), nil); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong key should return ErrDecrypt, got %v", err)
	}

	// 3. Unset multiple keys.
	if err := UnsetKeys(path, ageKey, []string{"MULTILINE", "db.password"}); err != nil {
		t.Fatalf("UnsetKeys: %v", err)
	}
	meta, err = InspectFile(path)
	if err != nil {
		t.Fatalf("InspectFile after unset: %v", err)
	}
	if len(meta.Keys) != 1 || meta.Keys[0].Path != "GH_TOKEN" {
		t.Fatalf("unexpected keys after unset: %+v", meta.Keys)
	}

	// 4. Tamper with file -> MAC verification must fail with ErrDecrypt.
	tampered := strings.Replace(string(rawAfter), "lastmodified: ", "lastmodified: 1999-01-01T00:00:00Z #", 1)
	tamperedPath := filepath.Join(dir, "tampered.enc.yaml")
	if err := os.WriteFile(tamperedPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(tamperedPath, ageKey, nil); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered file should fail MAC verification with ErrDecrypt, got %v", err)
	}
}

func TestOfficialSopsCLIInterop(t *testing.T) {
	sopsBin, err := exec.LookPath("sops")
	if err != nil {
		t.Skip("official sops binary not installed; skipping bidirectional interop test")
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ageKeyStr := id.String()
	recipient := id.Recipient().String()
	dir := t.TempDir()

	// Direction A: sopsage creates/sets/unsets -> official `sops decrypt` validates MAC and decrypts!
	oursPath := filepath.Join(dir, "ours.enc.yaml")
	if err := InitFile(oursPath, []string{recipient}); err != nil {
		t.Fatalf("InitFile: %v", err)
	}
	if err := SetKeys(oursPath, []byte(ageKeyStr), []KV{
		{Key: "API_KEY", Value: []byte("sk-live-12345")},
		{Key: "nested.token", Value: []byte("tok-nested-999")},
		{Key: "TEMP_KEY", Value: []byte("to-delete")},
	}); err != nil {
		t.Fatalf("SetKeys: %v", err)
	}
	if err := UnsetKeys(oursPath, []byte(ageKeyStr), []string{"TEMP_KEY"}); err != nil {
		t.Fatalf("UnsetKeys: %v", err)
	}

	cmd := exec.Command(sopsBin, "decrypt", oursPath)
	cmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+ageKeyStr)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("official sops failed to decrypt sopsage file: %v\noutput:\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "API_KEY: sk-live-12345") || !strings.Contains(string(out), "token: tok-nested-999") {
		t.Fatalf("unexpected official sops decrypted output:\n%s", string(out))
	}

	// Direction B: official `sops encrypt` + `sops set` -> sopsage decrypts & verifies MAC!
	plainPath := filepath.Join(dir, "plain.yaml")
	plainYAML := "APP_SECRET: \"hello-from-official-sops\"\nCOUNT: 42\nENABLED: true\ndb:\n  pass: \"db-s3cr3t\"\n"
	if err := os.WriteFile(plainPath, []byte(plainYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	officialPath := filepath.Join(dir, "official.enc.yaml")
	encCmd := exec.Command(sopsBin, "encrypt", "--age", recipient, "--output", officialPath, plainPath)
	if out, err := encCmd.CombinedOutput(); err != nil {
		t.Fatalf("official sops encrypt failed: %v\n%s", err, string(out))
	}

	got, err := Decrypt(officialPath, []byte(ageKeyStr), nil)
	if err != nil {
		t.Fatalf("sopsage failed to decrypt official sops file: %v", err)
	}
	defer WipeKVs(got)

	gotMap := make(map[string]string, len(got))
	for _, kv := range got {
		gotMap[kv.Key] = string(kv.Value)
	}
	if gotMap["APP_SECRET"] != "hello-from-official-sops" ||
		gotMap["COUNT"] != "42" ||
		gotMap["ENABLED"] != "true" ||
		gotMap["db.pass"] != "db-s3cr3t" {
		t.Fatalf("unexpected values from official sops file: %+v", gotMap)
	}

	// Mutate the official file with sopsage.SetKeys, then verify official sops still decrypts it cleanly!
	if err := SetKeys(officialPath, []byte(ageKeyStr), []KV{{Key: "ADDED_BY_OUTSIDER", Value: []byte("ok-interop")}}); err != nil {
		t.Fatalf("SetKeys on official file: %v", err)
	}
	decCmd := exec.Command(sopsBin, "decrypt", "--extract", `["ADDED_BY_OUTSIDER"]`, officialPath)
	decCmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+ageKeyStr)
	valOut, err := decCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("official sops failed to decrypt after sopsage SetKeys: %v\n%s", err, string(valOut))
	}
	if strings.TrimSpace(string(valOut)) != "ok-interop" {
		t.Fatalf("official sops extract = %q, want ok-interop", string(valOut))
	}
}

func TestFormatMultiKey(t *testing.T) {
	kvs := []KV{
		{Key: "A", Value: []byte("simple")},
		{Key: "B", Value: []byte("hello world\n$100 \"quoted\"")},
	}
	dotenv, err := FormatMultiKey(kvs, "dotenv")
	if err != nil {
		t.Fatalf("dotenv: %v", err)
	}
	wantDotenv := "A=simple\nB=\"hello world\\n\\$100 \\\"quoted\\\"\"\n"
	if string(dotenv) != wantDotenv {
		t.Fatalf("dotenv =\n%s\nwant:\n%s", string(dotenv), wantDotenv)
	}

	nested := []KV{{Key: "db.pass", Value: []byte("pw")}}
	if _, err := FormatMultiKey(nested, "dotenv"); err == nil {
		t.Fatalf("nested key in dotenv should fail")
	}
	j, err := FormatMultiKey(nested, "json")
	if err != nil || !strings.Contains(string(j), `"pass": "pw"`) {
		t.Fatalf("json format failed: %v %s", err, string(j))
	}
	y, err := FormatMultiKey(nested, "yaml")
	if err != nil || !strings.Contains(string(y), "pass: pw") {
		t.Fatalf("yaml format failed: %v %s", err, string(y))
	}
}

func TestWebKeygenInterop(t *testing.T) {
	// Keys generated by web/app.js generateAgeSecretKey() must parse cleanly in filippo.io/age
	// and work end-to-end with sopsage InitFile + SetKeys + Decrypt.
	vectors := []string{
		"AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ8H00W3",
		"AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE",
	}

	if nodeBin, err := exec.LookPath("node"); err == nil {
		cmd := exec.Command(nodeBin, "-e", `import("../../web/app.js").then(() => console.log(globalThis.__OUTSIDER_CRYPTO__.generateAgeSecretKey()))`)
		if out, err := cmd.Output(); err == nil {
			vectors = append(vectors, strings.TrimSpace(string(out)))
		}
	}

	for _, rawKey := range vectors {
		id, err := ParseAgeIdentity([]byte(rawKey))
		if err != nil {
			t.Fatalf("ParseAgeIdentity(%q) failed: %v", rawKey, err)
		}
		recipient := id.Recipient().String()
		if err := ValidateRecipient(recipient); err != nil {
			t.Fatalf("derived recipient invalid: %v", err)
		}
		path := filepath.Join(t.TempDir(), "webgen.enc.yaml")
		if err := InitFile(path, []string{recipient}); err != nil {
			t.Fatalf("InitFile with web-generated key: %v", err)
		}
		if err := SetKeys(path, []byte(rawKey), []KV{{Key: "TOKEN", Value: []byte("ok")}}); err != nil {
			t.Fatalf("SetKeys with web-generated key: %v", err)
		}
		got, err := Decrypt(path, []byte(rawKey), []string{"TOKEN"})
		if err != nil || len(got) != 1 || string(got[0].Value) != "ok" {
			t.Fatalf("Decrypt with web-generated key failed: %v %+v", err, got)
		}
		WipeKVs(got)
	}
}
