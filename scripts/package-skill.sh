#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/dist"
STAGE_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "${STAGE_DIR}"
}
trap cleanup EXIT

mkdir -p "${STAGE_DIR}/outsider/references" "${OUT_DIR}"
cp "${ROOT_DIR}/docs/SKILL.md" "${STAGE_DIR}/outsider/SKILL.md"
cp -R "${ROOT_DIR}/docs/references/." "${STAGE_DIR}/outsider/references/"

ARCHIVE="${OUT_DIR}/outsider-skill.tar.gz"
tar -czf "${ARCHIVE}" -C "${STAGE_DIR}" outsider

echo "[package-skill] Created ${ARCHIVE}"
