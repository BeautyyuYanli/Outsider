---
name: outsider
description: Request temporary secrets out-of-band via human approval without storing plaintext on disk or exposing secrets to LLM context. Use whenever a task requires a sensitive token, password, SSH key, or SOPS decryption key that is not present in the local environment.
---

# Outsider — Out-of-Band Secret Handoff

Execute Outsider via `uvx` from GitHub's `main` branch to request a human-approved secret and inject it directly into a target command's process memory. Plaintext secrets never touch disk or enter the conversation context.

```bash
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider ...
```

## When to Trigger

- A command requires a sensitive credential (API token, database password, SSH key/passphrase, SOPS `age` key, release token) that is not already configured in the environment.
- For projects managing multi-variable `.env` secrets with SOPS (`.env.enc`), request only the single-line `SOPS_AGE_KEY` and compose with `sops exec-env` or `sops exec-file`.

## Command Pattern

```bash
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name "<short-ascii-name>" \
  --reason "<clear explanation of why and what will run>" \
  <handoff-flag> \
  -- <target-command> [args...]
```

### Handoff Mode Priority

Always pick the safest handoff mode supported by the target tool, in this order:

1. **`--stdin`** or **`--askpass`** (pipe / one-shot Unix socket)
2. **`--env VAR`** or **`--env VAR="prefix_{{secret}}"`** (child process env only)
3. **`--file`** (`{{file}}` placeholder) or **`--file-env VAR`** (`/dev/shm` `0600` temp file, scrubbed on exit)
4. **`--arg-placeholder "{{secret}}"`** (last resort only; visible in `ps`)

See [references/handoff-examples.md](references/handoff-examples.md) for concrete tool recipes (`sops`, `gh`, `psql`, `ssh`, `git`, `kubectl`, `curl`, `rclone`, `openssl`).

## Hard Security Rules

1. **Never exfiltrate or print secrets**: Never run `echo`, `printenv`, `env`, `cat {{file}}`, or write secrets to workspace files inside the target command.
2. **Avoid disk-persisting login commands**: Prefer stateless per-command injection (e.g., `--env GH_TOKEN -- gh release create ...`) over commands that persist credentials to disk (such as `gh auth login` or `docker login`).
3. **Clear approval context**:
   - `--name` MUST be a concise, consistent ASCII identifier (e.g., `prod-db`, `gh-release`, `myproject-sops`), because it also forms the Bitwarden prefix URL `/approve/<name-slug>/`.
   - `--reason` MUST clearly state why the secret is needed right now.
4. **No retry loops on timeout**: If `outsider` exits with code `102` (approval expired/cancelled), inform the user and ask whether to retry. Never automatically re-trigger notifications in a loop.

## Exit Codes

- `0` (or target exit code): Target command executed.
- `100`: Local config or CLI argument error (diagnose with `uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider doctor`).
- `101`: Relay unreachable or device public key not authorized.
- `102`: Approval timed out or cancelled.
- `103`: Ciphertext decryption or AAD integrity check failed.
