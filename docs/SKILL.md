---
name: outsider
description: Request temporary secrets out-of-band via human approval without storing plaintext on disk or exposing secrets to LLM context. Use whenever a task requires a sensitive token, password, SSH key, or SOPS decryption key that is not present in the local environment.
---

# Outsider — Out-of-Band Secret Handoff

Execute Outsider via `uvx` from GitHub's `main` branch so plaintext secrets stay in process memory and never touch disk or LLM context:

```bash
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider ...
```

## Discovery First (Zero Approvals)

Before requesting any secret, inspect what is already registered locally:

1. **List registered approval names** (Direct & SOPS keys):
   ```bash
   uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider name ls
   ```
2. **Inspect keys in a SOPS file** (plaintext key paths, no private key needed):
   ```bash
   uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider sops keys ~/.secrets.enc.yaml
   ```

## Standard SOPS Path (Default)

Outsider has a built-in pure-Go SOPS (`age`) engine—no external `sops` or `age` binary is needed. `SOPS_AGE_KEY` is used only in memory to decrypt the file and is wiped immediately (never passed to the child process).

1. **Inject all top-level keys as env vars** (auto-resolves `--name` from `config.toml` via the file's `age1...` recipient, or pass `--name <slug>` explicitly):
   ```bash
   uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
     --sops ~/.secrets.enc.yaml \
     --reason "<why this command needs the secret>" \
     --env-all \
     -- <target-command> [args...]
   ```
2. **Least-privilege single/multi-key injection** (`--sops-key` supports dot paths like `db.password`, and combines with `--env`, `--stdin`, `--file`, `--askpass`):
   ```bash
   uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
     --sops ~/.secrets.enc.yaml \
     --sops-key GH_TOKEN \
     --reason "Check GitHub auth status" \
     --env GH_TOKEN \
     -- gh auth status
   ```
3. **Manage SOPS files** (`init`, `set`, `unset`):
   - `outsider sops init <file> --name <slug> [--desc "..."]` — creates a new SOPS YAML (0 approvals if `<slug>` already has a registered SOPS key; 1 approval with in-browser `age` keygen otherwise).
   - `outsider sops set <file> <KEY>...` — collects new secret value(s) first, then unlocks `SOPS_AGE_KEY` last (supports `--stdin` for single key).
   - `outsider sops unset <file> <KEY>...` — removes one or more keys in one approval.
   - See [references/handoff-examples.md](references/handoff-examples.md) for full examples.

## Direct Single-Secret Path

When a one-off secret is not stored in SOPS, inject it directly using the safest mode supported (`--stdin` / `--askpass` > `--env VAR` > `--file` / `--file-env VAR`):

```bash
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name "<short-ascii-name>" \
  --reason "<clear explanation>" \
  <handoff-flag> \
  -- <target-command> [args...]
```

Pass `--save-name [--desc "..."]` only if the user wants to register a verified Direct name into `config.toml` on successful approval.

## Hard Security Rules

1. **Never print or persist secrets**: Never run `echo`, `printenv`, `env`, `cat {{file}}`, or write secrets to disk; avoid disk-persisting logins like `gh auth login`.
2. **Minimum privilege**: Prefer `--sops-key <KEY>` over `--env-all` when only one or a few keys are needed.
3. **Clear approval context**: Always pass a concise ASCII `--name` (used for Bitwarden `/approve/<name>/` matching) and a specific `--reason`.
4. **No retry loops on timeout**: If `outsider` exits with `102`, inform the user and ask before retrying.

## Exit Codes

- `0` (or target exit code): Target command executed.
- `100`: Local config, argument, or SOPS metadata error (run `outsider doctor` via `uvx`).
- `101`: Relay unreachable or device key unauthorized.
- `102`: Approval timed out or cancelled.
- `103`: E2EE or SOPS decryption / integrity check failed.
