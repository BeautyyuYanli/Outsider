#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-$(rustc -vV | awk '/^host:/ {print $2}')}"
OUT_DIR="${ROOT_DIR}/dist"
STAGE_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "${STAGE_DIR}"
}
trap cleanup EXIT

echo "[package-skill] Building outsider CLI for target: ${TARGET}"
cargo build --release --manifest-path "${ROOT_DIR}/cli/Cargo.toml" --target "${TARGET}"

BIN_EXT=""
if [[ "${TARGET}" == *windows* ]]; then
  BIN_EXT=".exe"
fi

BIN_PATH="${ROOT_DIR}/cli/target/${TARGET}/release/outsider${BIN_EXT}"
if [[ ! -f "${BIN_PATH}" ]]; then
  echo "[package-skill] Error: expected binary not found at ${BIN_PATH}" >&2
  exit 1
fi

mkdir -p "${STAGE_DIR}/outsider/bin" "${STAGE_DIR}/outsider/references" "${OUT_DIR}"
cp "${ROOT_DIR}/docs/SKILL.md" "${STAGE_DIR}/outsider/SKILL.md"
cp -R "${ROOT_DIR}/docs/references/." "${STAGE_DIR}/outsider/references/"
cp "${BIN_PATH}" "${STAGE_DIR}/outsider/bin/outsider${BIN_EXT}"
chmod +x "${STAGE_DIR}/outsider/bin/outsider${BIN_EXT}"

ARCHIVE="${OUT_DIR}/outsider-skill-${TARGET}.tar.gz"
tar -czf "${ARCHIVE}" -C "${STAGE_DIR}" outsider

echo "[package-skill] Created ${ARCHIVE}"
