---
name: outsider
description: Use when a task requires a secret (token, password, SSH key, API key) not present locally, or when inspecting, initializing, or updating encrypted SOPS secret files and Outsider approval names.
---

# Outsider — Out-of-Band Secret Handoff

Invoke `outsider` via `uvx` from GitHub `main` (plaintexts stay in process memory, never on disk or in LLM context):

```bash
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider <subcommand> ...
```

All examples below write `outsider` as shorthand for that `uvx` command. Run `outsider <subcommand> --help` for full flags.

## 1. Discover Locally First (0 Approvals)

```bash
outsider name ls                           # list registered Direct & SOPS names, descriptions, age1... recipients
outsider sops keys ~/.secrets.enc.yaml     # list plaintext leaf key paths in a SOPS YAML file
outsider doctor                            # verify config, identity key, and relay auth
```

## 2. Run with SOPS (Default)

Built-in SOPS (`age`) engine—no external `sops`/`age` binaries needed. `--name` auto-resolves from `config.toml` via the file's `age1...` recipient, and `SOPS_AGE_KEY` is wiped before starting the target command.

```bash
# Least privilege: extract specific key(s) (dot paths supported, e.g. db.password)
outsider run --sops ~/.secrets.enc.yaml --sops-key GH_TOKEN \
  --reason "Check GitHub auth status" --env GH_TOKEN -- gh auth status

# Inject all top-level keys as env vars (or use --file --file-format dotenv|yaml|json)
outsider run --sops ~/.secrets.enc.yaml \
  --reason "<why this command needs the secrets>" --env-all -- <target-command> [args...]
```

## 3. Run with Direct Secret

For one-off secrets not in SOPS. Handoff priority: `--stdin` / `--askpass` > `--env VAR` > `--file` / `--file-env VAR` > `--arg-placeholder`.

```bash
outsider run --name "<short-ascii-slug>" --reason "<clear explanation>" \
  <handoff-flag> -- <target-command> [args...]
```

Add `--save-name` only when registering a verified Direct name into `config.toml`.

## 4. Manage SOPS Stores & Approval Names

```bash
# SOPS files (init: 0 approvals if --name is registered, 1 with browser age-keygen otherwise)
outsider sops init <file> --name <slug> [--desc "..."]
outsider sops set <file> <KEY>...
openssl rand -hex 32 | outsider sops set <file> <KEY> --stdin   # store locally generated secret (1 approval)
outsider sops unset <file> <KEY>...

# Registered names in config.toml (add requires real approval; set/rm are local-only)
outsider name add <slug> [--sops] [--desc "..."]
outsider name set <slug> --desc "..."
outsider name rm <slug>
```

## Hard Security Rules

1. **Never print or persist secrets**: Never run `echo`, `printenv`, `env`, `cat {{file}}`, or disk-persisting logins like `gh auth login`.
2. **Minimum privilege**: Prefer `--sops-key <KEY>` over `--env-all`, and safest handoff (`--stdin` / `--askpass` > `--env` > `--file`).
3. **Clear approval context**: Pass a concise ASCII `--name` (matched by password managers at `/approve/<name>/`) and a specific `--reason`.
4. **No retry loops on timeout**: If `outsider` exits with `102`, inform the user and ask before retrying.

## Exit Codes

- `0` (or target exit code): Target command executed.
- `100`: Local config, argument, or SOPS metadata error (`outsider doctor`).
- `101`: Relay unreachable or device key unauthorized (`outsider doctor` / `outsider id`).
- `102`: Approval timed out or cancelled.
- `103`: E2EE or SOPS decryption / integrity check failed.
