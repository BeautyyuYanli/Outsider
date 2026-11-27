---
name: outsider
description: Request temporary secrets out-of-band via human approval without storing plaintext on disk or exposing secrets to LLM context. Use whenever a task requires a sensitive token, password, SSH key, or SOPS decryption key that is not present in the local environment.
---

# Outsider — Out-of-Band Secret Handoff

Execute Outsider via `uvx` from GitHub's `main` branch so plaintext secrets stay in process memory and never touch disk or LLM context:

```bash
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider ...
```

## Standard SOPS Path (Default)

Prefer SOPS (`age`) flat YAML files (`~/.secrets.enc.yaml` for personal secrets, `secrets.enc.yaml` for project secrets) so you only ever request `SOPS_AGE_KEY`:

1. **Inspect keys first**: Key names in SOPS YAML are plaintext—read the file directly to confirm the needed key exists before requesting approval.
2. **Decrypt & run**: Request `--env SOPS_AGE_KEY` (`--name personal-sops` for `~/.secrets.enc.yaml`, or `--name <project>-sops`) and run with `sops exec-env`:
   ```bash
   uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
     --name "personal-sops" \
     --reason "<why this command needs the secret>" \
     --env SOPS_AGE_KEY \
     -- sops exec-env ~/.secrets.enc.yaml "<target-command>"
   ```
3. **Add / update a key**: Use nested two-stage `outsider` (`SOPS_AGE_KEY` + new value) piped into `sops set --value-stdin`. See [references/handoff-examples.md](references/handoff-examples.md).

## Single-Secret Fallback

When a one-off secret is not in SOPS, inject it directly using the safest mode supported (`--stdin` / `--askpass` > `--env VAR` > `--file` / `--file-env VAR`):

```bash
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name "<short-ascii-name>" \
  --reason "<clear explanation>" \
  <handoff-flag> \
  -- <target-command> [args...]
```

## Hard Security Rules

1. **Never print or persist secrets**: Never run `echo`, `printenv`, `env`, `cat {{file}}`, or write secrets to disk; avoid disk-persisting logins like `gh auth login`.
2. **Clear approval context**: Always pass a concise ASCII `--name` (used for Bitwarden `/approve/<name>/` matching) and a specific `--reason`.
3. **No retry loops on timeout**: If `outsider` exits with `102`, inform the user and ask before retrying.

## Exit Codes

- `0` (or target exit code): Target command executed.
- `100`: Local config or CLI error (run `outsider doctor` via `uvx`).
- `101`: Relay unreachable or device key unauthorized.
- `102`: Approval timed out or cancelled.
- `103`: Decryption or integrity check failed.
