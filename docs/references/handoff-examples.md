# Outsider Reference & Examples

Canonical commands using `uvx` from GitHub `main` (`OUT="uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider"`).

## 1. Local Discovery (Zero Approvals)

```bash
# List verified Direct & SOPS approval names in ~/.config/outsider/config.toml
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider name ls

# List plaintext key paths inside a SOPS YAML file
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider sops keys ~/.secrets.enc.yaml

# Update description of an existing registered name (local-only metadata)
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider name set personal-sops --desc "Personal SOPS age key"
```

## 2. Run Commands with Native SOPS Decryption

`--name` is optional when the file's `age1...` recipient matches a registered SOPS key in `config.toml`. `SOPS_AGE_KEY` is wiped before starting the target command.

```bash
# Inject all top-level keys as environment variables
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --sops ~/.secrets.enc.yaml \
  --reason "Run integration tests with project secrets" \
  --env-all \
  -- pytest tests/integration/

# Least-privilege: inject a single key (supports dot paths like db.password) into --env / --stdin / --askpass / --file
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --sops ~/.secrets.enc.yaml \
  --sops-key db.password \
  --reason "Run production database migration" \
  --env PGPASSWORD \
  -- psql -h db.prod -U admin -d app -f migrate.sql

# Pass decrypted keys as a temporary 0600 file (--file-format: dotenv | json | yaml)
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --sops ~/.secrets.enc.yaml \
  --reason "Start docker compose stack" \
  --file --file-format dotenv \
  -- docker compose --env-file {{file}} up -d
```

## 3. Manage SOPS Files (`init` / `set` / `unset`)

```bash
# Initialize a new SOPS file (0 approvals if personal-sops is already registered;
# 1 approval with in-browser age keygen button on first enrollment)
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider sops init \
  ~/.secrets.enc.yaml --name personal-sops --desc "Personal SOPS age key"

# Add or update one or more keys (collects new values first, unlocks SOPS_AGE_KEY last)
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider sops set \
  ~/.secrets.enc.yaml GH_TOKEN db.password

# Write a locally generated value into SOPS without revealing it to LLM context (1 approval for SOPS_AGE_KEY)
openssl rand -hex 32 | uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider sops set \
  ~/.secrets.enc.yaml JWT_SECRET --stdin

# Remove one or more keys in a single approval
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider sops unset \
  ~/.secrets.enc.yaml OLD_KEY legacy.token
```

## 4. Direct Single-Secret Handoff (Without SOPS)

```bash
# Stdin (safest for CLIs supporting password-stdin)
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name docker-pat --reason "Push release image" --stdin \
  -- docker login -u myuser --password-stdin

# ASKPASS (SSH / Git / sudo)
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name ssh-key-pass --reason "Push tag to remote" --askpass \
  -- git push origin v1.2.0

# Enroll a verified name into config.toml explicitly
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider name add \
  personal-sops --sops --desc "Personal SOPS age key"
```
