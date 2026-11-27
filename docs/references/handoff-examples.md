# Outsider + SOPS Reference

Canonical commands using `uvx` from GitHub `main` and flat SOPS YAML (`~/.secrets.enc.yaml` with `--name personal-sops`, or project `secrets.enc.yaml` with `--name <project>-sops`).

## 1. Decrypt & Inject Env Vars (Default)

```bash
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name "personal-sops" \
  --reason "Run command with secrets" \
  --env SOPS_AGE_KEY \
  -- sops exec-env ~/.secrets.enc.yaml "<command>"
```

## 2. Pass as Temporary `--env-file` (e.g. `docker compose`)

```bash
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name "personal-sops" \
  --reason "Start compose stack" \
  --env SOPS_AGE_KEY \
  -- sops exec-file --output-type dotenv ~/.secrets.enc.yaml "docker compose --env-file {} up -d"
```

## 3. Append / Update a Key (Zero Plaintext Exposure)

```bash
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name "personal-sops" \
  --reason "Step 1/2: Unlock ~/.secrets.enc.yaml to set NEW_KEY" \
  --env SOPS_AGE_KEY \
  -- uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
    --name "new-key" \
    --reason "Step 2/2: Provide value for NEW_KEY" \
    --env NEW_SECRET_VAL \
    -- sh -c 'set -eu; python3 -c "import json, os, sys; sys.stdout.write(json.dumps(os.environ[\"NEW_SECRET_VAL\"]))" | sops set --value-stdin "$HOME/.secrets.enc.yaml" '\''["NEW_KEY"]'\'''
```

## 4. Remove a Key

```bash
uvx --from 'git+https://github.com/BeautyyuYanli/Outsider@main#subdirectory=cli' outsider run \
  --name "personal-sops" \
  --reason "Remove OLD_KEY from ~/.secrets.enc.yaml" \
  --env SOPS_AGE_KEY \
  -- sops unset ~/.secrets.enc.yaml '["OLD_KEY"]'
```
