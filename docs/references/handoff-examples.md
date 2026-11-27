# Outsider Handoff Examples

All examples invoke `outsider` via `uvx` from GitHub's `main` branch and assume this device has been initialized (`outsider init`) and approved in `relay.toml`.

For brevity, define the command prefix (or invoke `uvx --from ...` directly):

```bash
OUTSIDER="uvx --from git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli outsider"
```

## 1. Multi-variable Secrets via SOPS (Recommended)

Store non-sensitive local config in `.env`, and encrypt sensitive variables into a flat YAML file (e.g. `secrets.enc.yaml` or `~/.secrets.enc.yaml`) with SOPS (`age`). Key names stay visible in plaintext; only values are encrypted. Keep only the single-line `AGE-SECRET-KEY-1...` in Bitwarden under `https://relay.example.com/approve/myproject-sops/`.

```bash
# Inject decrypted secrets into process memory (no plaintext file written)
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name "myproject-sops" \
  --reason "Run staging integration tests" \
  --env SOPS_AGE_KEY \
  -- sops exec-env secrets.enc.yaml "pytest tests/integration/"

# For tools requiring an --env-file path (e.g. docker compose)
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name "myproject-sops" \
  --reason "Start staging stack" \
  --env SOPS_AGE_KEY \
  -- sops exec-file --output-type dotenv secrets.enc.yaml "docker compose --env-file {} up -d"

# Append or update a single secret key without plaintext touching disk, ps, or LLM context
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name "personal-sops" \
  --reason "Step 1/2: Unlock ~/.secrets.enc.yaml to set NEW_KEY" \
  --env SOPS_AGE_KEY \
  -- uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
    --name "new-key" \
    --reason "Step 2/2: Provide secret value for NEW_KEY" \
    --env NEW_SECRET_VAL \
    -- sh -c 'set -eu; python3 -c "import json, os, sys; sys.stdout.write(json.dumps(os.environ[\"NEW_SECRET_VAL\"]))" | sops set --value-stdin "$HOME/.secrets.enc.yaml" '\''["NEW_KEY"]'\'''
```

## 2. GitHub CLI (`gh`) Without Persisting Token to Disk

Use `GH_TOKEN` instead of `gh auth login` so nothing is written to `~/.config/gh/hosts.yml`.

```bash
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name "gh-release" \
  --reason "Create GitHub release v1.2.0" \
  --env GH_TOKEN \
  -- gh release create v1.2.0 ./dist/*.tar.gz
```

## 3. PostgreSQL (`psql`)

```bash
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name "prod-db" \
  --reason "Run schema migration 0042" \
  --env PGPASSWORD \
  -- psql -h db.prod.internal -U migrator -d app -f migrations/0042.sql
```

## 4. Authenticated HTTP API (`curl`)

```bash
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name "cloudflare-api" \
  --reason "Purge CDN cache after deploy" \
  --env AUTH_HEADER="Authorization: Bearer {{secret}}" \
  -- sh -c 'curl -fsS -H "$AUTH_HEADER" -X POST https://api.cloudflare.com/client/v4/zones/ZONE_ID/purge_cache -d "{\"purge_everything\":true}"'
```

## 5. SSH Private Key / Kubeconfig / JSON Credentials (`--file`)

On Linux, `--file` writes the secret to a `0600` file in `/dev/shm` (RAM) and overwrites + deletes it as soon as the command exits.

```bash
# SSH private key
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name "prod-ssh-key" \
  --reason "Check systemd service status on prod-web-01" \
  --file \
  -- ssh -i {{file}} -o IdentitiesOnly=yes ops@prod-web-01 "systemctl status app"

# Kubeconfig
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name "prod-kubeconfig" \
  --reason "Inspect rollout status" \
  --file-env KUBECONFIG \
  -- kubectl rollout status deployment/api -n production
```

## 6. Passphrase-Protected SSH / Git / Sudo (`--askpass`)

```bash
# Git push over SSH/HTTPS with passphrase or token prompt
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name "git-ssh-passphrase" \
  --reason "Push release tag v1.2.0" \
  --askpass \
  -- git push origin v1.2.0

# Sudo without TTY prompt
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name "server-sudo" \
  --reason "Reload nginx config" \
  --askpass \
  -- sudo -A systemctl reload nginx
```

## 7. Standard Input Pipe (`--stdin`)

```bash
# Decrypt an OpenSSL encrypted archive
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name "backup-passphrase" \
  --reason "Verify backup integrity" \
  --stdin \
  -- openssl enc -d -aes-256-cbc -pbkdf2 -pass stdin -in backup.tar.gz.enc -out backup.tar.gz
```
