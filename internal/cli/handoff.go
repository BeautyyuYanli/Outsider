package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"outsider/internal/sopsage"
)

// allowExecReplace can be disabled in unit tests so ExecuteTarget returns an exit code instead of calling syscall.Exec.
var allowExecReplace = true

// HandoffKind identifies how secrets are transferred to the target command.
type HandoffKind int

const (
	HandoffNone HandoffKind = iota
	HandoffEnv
	HandoffEnvAll
	HandoffStdin
	HandoffFile
	HandoffAskpass
	HandoffArgPlaceholder
)

// HandoffSpec configures how decrypted secret(s) are passed to the child process.
type HandoffSpec struct {
	Kind           HandoffKind
	EnvSpec        string // --env VAR or VAR=prefix_{{secret}}
	StdinTemplate  string // --stdin-template
	HasStdinTmpl   bool
	NoStdinNewline bool
	FileEnvVar     string // --file-env VAR (empty means --file with {{file}} placeholder)
	FileFormat     string // dotenv | yaml | json (used for multi-key SOPS --file/--file-env)
	ArgPlaceholder string // --arg-placeholder
}

// HandoffPayload carries either a single secret or multiple SOPS KV pairs.
type HandoffPayload struct {
	Single []byte
	Multi  []sopsage.KV
	IsMulti bool
}

// Wipe zeroes all secret material in the payload.
func (p *HandoffPayload) Wipe() {
	if p == nil {
		return
	}
	clear(p.Single)
	p.Single = nil
	sopsage.WipeKVs(p.Multi)
	p.Multi = nil
}

// secretFileGuard tracks a 0600 temporary secret file and overwrites it with zeros before unlinking.
type secretFileGuard struct {
	path string
	size int
}

func (g *secretFileGuard) Close() {
	if g == nil || g.path == "" {
		return
	}
	if f, err := os.OpenFile(g.path, os.O_WRONLY, 0); err == nil {
		n := g.size
		if n < 64 {
			n = 64
		}
		zeros := make([]byte, n)
		_, _ = f.Write(zeros)
		_ = f.Sync()
		_ = f.Close()
	}
	_ = os.Remove(g.path)
	g.path = ""
}

func createSecretFile(content []byte) (*secretFileGuard, error) {
	baseDir := preferredTempDir()
	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	path := filepath.Join(baseDir, "outsider-"+base64.RawURLEncoding.EncodeToString(rnd[:])+".key")

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create temp secret file %s: %w", path, err)
	}
	if runtime.GOOS != "windows" {
		_ = f.Chmod(0o600)
	}
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write temp secret file %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("sync temp secret file %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("close temp secret file %s: %w", path, err)
	}
	return &secretFileGuard{path: path, size: len(content)}, nil
}

func prepareEnvPair(spec string, secret []byte) (string, string, error) {
	if k, tmpl, ok := strings.Cut(spec, "="); ok {
		key := strings.TrimSpace(k)
		if key == "" {
			return "", "", errors.New("environment variable name cannot be empty")
		}
		if !strings.Contains(tmpl, "{{secret}}") {
			return "", "", fmt.Errorf("--env template %q must contain `{{secret}}` placeholder", spec)
		}
		return key, strings.ReplaceAll(tmpl, "{{secret}}", string(secret)), nil
	}
	key := strings.TrimSpace(spec)
	if key == "" {
		return "", "", errors.New("environment variable name cannot be empty")
	}
	return key, string(secret), nil
}

func prepareStdinBytes(secret []byte, tmpl string, hasTmpl bool, noNewline bool) []byte {
	if hasTmpl {
		expanded := strings.ReplaceAll(tmpl, `\n`, "\n")
		return []byte(strings.ReplaceAll(expanded, "{{secret}}", string(secret)))
	}
	if noNewline || (len(secret) > 0 && secret[len(secret)-1] == '\n') {
		out := make([]byte, len(secret))
		copy(out, secret)
		return out
	}
	out := make([]byte, len(secret)+1)
	copy(out, secret)
	out[len(secret)] = '\n'
	return out
}

func mergeEnv(base []string, extra map[string]string) []string {
	out := make([]string, 0, len(base)+len(extra))
	for _, entry := range base {
		k, _, ok := strings.Cut(entry, "=")
		if ok {
			if _, overridden := extra[k]; overridden {
				continue
			}
		}
		out = append(out, entry)
	}
	for k, v := range extra {
		out = append(out, k+"="+v)
	}
	return out
}

// ExecuteTarget transfers the secret payload to commandArgs with native inherited stdout/stderr (no redaction)
// and immediately scrubs parent-process secret buffers.
func ExecuteTarget(spec HandoffSpec, payload *HandoffPayload, commandArgs []string) (int, error) {
	defer payload.Wipe()

	if len(commandArgs) == 0 {
		return ExitConfigOrArg, errors.New("missing target command after `--`")
	}

	argv := make([]string, len(commandArgs))
	copy(argv, commandArgs)

	extraEnv := make(map[string]string)
	var stdinPayload []byte
	var fileGuard *secretFileGuard
	var apGuard *askpassGuard
	defer func() {
		clear(stdinPayload)
		if fileGuard != nil {
			fileGuard.Close()
		}
		if apGuard != nil {
			apGuard.Close()
		}
	}()

	canExecInPlace := false

	switch spec.Kind {
	case HandoffEnv:
		if payload.IsMulti {
			return ExitConfigOrArg, errors.New("--env only supports a single secret; use --env-all or --file for multiple keys")
		}
		k, v, err := prepareEnvPair(spec.EnvSpec, payload.Single)
		if err != nil {
			return ExitConfigOrArg, err
		}
		extraEnv[k] = v
		canExecInPlace = true

	case HandoffEnvAll:
		if payload.IsMulti {
			for _, kv := range payload.Multi {
				extraEnv[kv.Key] = string(kv.Value)
			}
		} else if len(payload.Multi) == 1 {
			extraEnv[payload.Multi[0].Key] = string(payload.Multi[0].Value)
		} else {
			return ExitConfigOrArg, errors.New("--env-all requires --sops mode")
		}
		canExecInPlace = true

	case HandoffStdin:
		if payload.IsMulti {
			return ExitConfigOrArg, errors.New("--stdin only supports a single secret")
		}
		stdinPayload = prepareStdinBytes(payload.Single, spec.StdinTemplate, spec.HasStdinTmpl, spec.NoStdinNewline)

	case HandoffFile:
		var fileBytes []byte
		if payload.IsMulti {
			formatted, err := sopsage.FormatMultiKey(payload.Multi, spec.FileFormat)
			if err != nil {
				return ExitConfigOrArg, err
			}
			fileBytes = formatted
		} else {
			fileBytes = make([]byte, len(payload.Single))
			copy(fileBytes, payload.Single)
		}
		guard, err := createSecretFile(fileBytes)
		clear(fileBytes)
		if err != nil {
			return ExitConfigOrArg, err
		}
		fileGuard = guard
		if spec.FileEnvVar != "" {
			extraEnv[spec.FileEnvVar] = guard.path
		} else {
			replaced := false
			for i, a := range argv {
				if strings.Contains(a, "{{file}}") {
					argv[i] = strings.ReplaceAll(a, "{{file}}", guard.path)
					replaced = true
				}
			}
			if !replaced {
				return ExitConfigOrArg, errors.New("--file requires `{{file}}` placeholder in target command (or use --file-env VAR)")
			}
		}

	case HandoffAskpass:
		if payload.IsMulti {
			return ExitConfigOrArg, errors.New("--askpass only supports a single secret")
		}
		guard, envs, err := startAskpassServer(payload.Single)
		if err != nil {
			return ExitConfigOrArg, err
		}
		apGuard = guard
		for k, v := range envs {
			extraEnv[k] = v
		}

	case HandoffArgPlaceholder:
		if payload.IsMulti {
			return ExitConfigOrArg, errors.New("--arg-placeholder only supports a single secret")
		}
		if spec.ArgPlaceholder == "" {
			return ExitConfigOrArg, errors.New("--arg-placeholder cannot be empty")
		}
		replaced := false
		for i, a := range argv {
			if strings.Contains(a, spec.ArgPlaceholder) {
				argv[i] = strings.ReplaceAll(a, spec.ArgPlaceholder, string(payload.Single))
				replaced = true
			}
		}
		if !replaced {
			return ExitConfigOrArg, fmt.Errorf("placeholder %q not found in target command arguments", spec.ArgPlaceholder)
		}
		fmt.Fprintln(os.Stderr, "[outsider] Warning: passing secret via command-line arguments may be visible in process listings (ps).")
		canExecInPlace = true

	default:
		return ExitConfigOrArg, errors.New("must specify one handoff mode: --env, --env-all, --stdin, --file, --file-env, --askpass, or --arg-placeholder")
	}

	// Wipe source payload immediately before launching child.
	payload.Wipe()

	envSlice := os.Environ()
	if len(extraEnv) > 0 {
		envSlice = mergeEnv(envSlice, extraEnv)
	}

	// For handoff modes without post-exit cleanup resources on Unix, exec directly in place.
	if canExecInPlace && allowExecReplace && runtime.GOOS != "windows" {
		if err := replaceProcess(argv, envSlice); err != nil {
			return ExitConfigOrArg, err
		}
		return 0, nil
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = envSlice
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if stdinPayload != nil {
		cmd.Stdin = bytes.NewReader(stdinPayload)
	} else {
		cmd.Stdin = os.Stdin
	}

	if err := cmd.Start(); err != nil {
		return ExitConfigOrArg, fmt.Errorf("failed to spawn target command %q: %w", argv[0], err)
	}

	// Wipe stdin copy once process started (bytes.Reader holds slice ref; wait until cmd completes to clear).
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	select {
	case err := <-waitCh:
		if err == nil {
			return 0, nil
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return 1, nil
	case sig := <-sigCh:
		if cmd.Process != nil {
			_ = cmd.Process.Signal(sig)
			_ = cmd.Process.Kill()
		}
		<-waitCh
		return 130, nil
	}
}
