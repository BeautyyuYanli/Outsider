#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/dist/wheels"
mkdir -p "${OUT_DIR}"

echo "[build-wheels] Building standalone outsider wheel (Rust CLI)..."
uv build --wheel --out-dir "${OUT_DIR}" "${ROOT_DIR}/cli"

echo "[build-wheels] Building standalone outsider-relay wheel (Go Relay + embedded Web UI)..."
uv build --wheel --out-dir "${OUT_DIR}" "${ROOT_DIR}/relay"

echo "[build-wheels] Built wheels:"
ls -lh "${OUT_DIR}"/*.whl
