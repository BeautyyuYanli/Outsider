#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/dist"
SKILL_DIR="${OUT_DIR}/skill/outsider"

rm -rf "${SKILL_DIR}"
mkdir -p "${SKILL_DIR}" "${OUT_DIR}"
cp "${ROOT_DIR}/docs/SKILL.md" "${SKILL_DIR}/SKILL.md"
if [[ -d "${ROOT_DIR}/docs/references" ]]; then
  mkdir -p "${SKILL_DIR}/references"
  cp -R "${ROOT_DIR}/docs/references/." "${SKILL_DIR}/references/"
fi

ARCHIVE="${OUT_DIR}/outsider-skill.tar.gz"
tar -czf "${ARCHIVE}" -C "${OUT_DIR}/skill" outsider

echo "[package-skill] Staged  ${SKILL_DIR}"
echo "[package-skill] Created ${ARCHIVE}"
