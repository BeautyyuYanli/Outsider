"""Minimal zero-dependency PEP 517 build backend for Outsider native binaries.

Packages compiled Rust (`outsider`) and/or Go (`outsider-relay`) executables
directly into PEP 427 `.data/scripts/` so `uvx` runs native binaries with zero
Python wrapper overhead and clean signal/exec semantics.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path


def _load_project_meta(project_dir: Path) -> tuple[str, str, str, str]:
    data = tomllib.loads((project_dir / "pyproject.toml").read_text(encoding="utf-8"))
    proj = data["project"]
    return (
        proj["name"],
        proj["version"],
        proj.get("description", ""),
        proj.get("requires-python", ""),
    )


def _normalize_dist_name(name: str) -> str:
    return name.replace("-", "_")


def _platform_tag() -> str:
    override = os.environ.get("OUTSIDER_WHEEL_TAG", "").strip()
    if override:
        return override
    return sysconfig.get_platform().replace("-", "_").replace(".", "_")


def _exe_suffix() -> str:
    goos = os.environ.get("GOOS", "").strip().lower()
    cargo_target = os.environ.get("OUTSIDER_CARGO_TARGET", "").strip().lower()
    if goos == "windows" or "windows" in cargo_target:
        return ".exe"
    if not goos and not cargo_target and sys.platform == "win32":
        return ".exe"
    return ""


def _build_rust_cli(repo_root: Path) -> Path:
    if shutil.which("cargo") is None:
        raise RuntimeError(
            "cargo (Rust toolchain) is required to build `outsider` from source. "
            "If you only need `outsider-relay`, use `#subdirectory=relay`."
        )
    cli_dir = repo_root / "cli" if (repo_root / "cli" / "Cargo.toml").is_file() else repo_root
    manifest = cli_dir / "Cargo.toml"
    if not manifest.is_file():
        raise RuntimeError(f"Cargo.toml not found under {repo_root}")

    cmd = ["cargo", "build", "--release", "--manifest-path", str(manifest)]
    target = os.environ.get("OUTSIDER_CARGO_TARGET", "").strip()
    if target:
        cmd.extend(["--target", target])
    subprocess.run(cmd, cwd=str(cli_dir), check=True)

    ext = _exe_suffix()
    cargo_target_dir = os.environ.get("CARGO_TARGET_DIR", "").strip()
    target_root = Path(cargo_target_dir) if cargo_target_dir else cli_dir / "target"
    if target:
        bin_path = target_root / target / "release" / f"outsider{ext}"
    else:
        bin_path = target_root / "release" / f"outsider{ext}"
    if not bin_path.is_file():
        raise RuntimeError(f"built outsider binary not found at {bin_path}")
    return bin_path


def _build_go_relay(repo_root: Path, out_dir: Path) -> Path:
    if shutil.which("go") is None:
        raise RuntimeError(
            "go (Go toolchain) is required to build `outsider-relay` from source. "
            "If you only need `outsider`, use `#subdirectory=cli`."
        )
    if not (repo_root / "go.mod").is_file():
        raise RuntimeError(f"go.mod not found under {repo_root}")

    ext = _exe_suffix()
    out_path = out_dir / f"outsider-relay{ext}"
    env = os.environ.copy()
    env.setdefault("CGO_ENABLED", "0")
    cmd = ["go", "build", "-trimpath", "-o", str(out_path), "./relay/cmd/outsider-relay"]
    subprocess.run(cmd, cwd=str(repo_root), env=env, check=True)
    if not out_path.is_file():
        raise RuntimeError(f"built outsider-relay binary not found at {out_path}")
    return out_path


def _record_entry(arcname: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
    return f"{arcname},sha256={digest},{len(data)}"


def _write_zip_file(zf: zipfile.ZipFile, arcname: str, data: bytes, executable: bool = False) -> str:
    zi = zipfile.ZipInfo(arcname)
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.create_system = 3  # Unix
    zi.external_attr = (0o100755 if executable else 0o100644) << 16
    zf.writestr(zi, data)
    return _record_entry(arcname, data)


def _metadata_bytes(name: str, version: str, summary: str, requires_python: str) -> bytes:
    lines = [
        "Metadata-Version: 2.1",
        f"Name: {name}",
        f"Version: {version}",
    ]
    if summary:
        lines.append(f"Summary: {summary}")
    if requires_python:
        lines.append(f"Requires-Python: {requires_python}")
    lines.append("")
    return "\n".join(lines).encode("utf-8")


def _wheel_bytes(tag: str) -> bytes:
    return (
        "Wheel-Version: 1.0\n"
        "Generator: outsider-pep517\n"
        "Root-Is-Purelib: false\n"
        f"Tag: {tag}\n"
    ).encode("utf-8")


def build_wheel_for_targets(
    project_dir: Path,
    repo_root: Path,
    targets: list[str],
    wheel_directory: str,
) -> str:
    name, version, summary, requires_python = _load_project_meta(project_dir)
    dist = _normalize_dist_name(name)
    plat_tag = _platform_tag()
    tag = f"py3-none-{plat_tag}"
    wheel_name = f"{dist}-{version}-{tag}.whl"
    wheel_path = Path(wheel_directory) / wheel_name

    dist_info = f"{dist}-{version}.dist-info"
    scripts_dir = f"{dist}-{version}.data/scripts"

    with tempfile.TemporaryDirectory(prefix="outsider-wheel-") as tmp:
        tmp_path = Path(tmp)
        binaries: list[tuple[str, Path]] = []
        ext = _exe_suffix()

        if "cli" in targets:
            binaries.append((f"outsider{ext}", _build_rust_cli(repo_root)))
        if "relay" in targets:
            binaries.append((f"outsider-relay{ext}", _build_go_relay(repo_root, tmp_path)))

        records: list[str] = []
        with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for bin_name, bin_path in binaries:
                raw = bin_path.read_bytes()
                records.append(_write_zip_file(zf, f"{scripts_dir}/{bin_name}", raw, executable=True))

            records.append(
                _write_zip_file(
                    zf,
                    f"{dist_info}/METADATA",
                    _metadata_bytes(name, version, summary, requires_python),
                )
            )
            records.append(_write_zip_file(zf, f"{dist_info}/WHEEL", _wheel_bytes(tag)))

            record_arc = f"{dist_info}/RECORD"
            records.append(f"{record_arc},,")
            _write_zip_file(zf, record_arc, ("\n".join(records) + "\n").encode("utf-8"))

    return wheel_name


def prepare_metadata_for_project(project_dir: Path, metadata_directory: str) -> str:
    name, version, summary, requires_python = _load_project_meta(project_dir)
    dist = _normalize_dist_name(name)
    tag = f"py3-none-{_platform_tag()}"
    dist_info_name = f"{dist}-{version}.dist-info"
    dist_info_dir = Path(metadata_directory) / dist_info_name
    dist_info_dir.mkdir(parents=True, exist_ok=True)
    (dist_info_dir / "METADATA").write_bytes(_metadata_bytes(name, version, summary, requires_python))
    (dist_info_dir / "WHEEL").write_bytes(_wheel_bytes(tag))
    return dist_info_name


def _should_skip_sdist(rel: Path) -> bool:
    skip_parts = {".git", "target", "dist", "skills", "__pycache__", ".venv"}
    return any(part in skip_parts for part in rel.parts) or rel.suffix == ".pyc"


def build_sdist_for_project(
    project_dir: Path,
    entries: list[tuple[Path, str]],
    sdist_directory: str,
    bundle_backend_as: str | None = None,
    exclude_arcs: set[str] | None = None,
) -> str:
    name, version, summary, requires_python = _load_project_meta(project_dir)
    dist = _normalize_dist_name(name)
    top = f"{dist}-{version}"
    tar_name = f"{top}.tar.gz"
    tar_path = Path(sdist_directory) / tar_name
    excluded = exclude_arcs or set()

    with tarfile.open(tar_path, "w:gz") as tf:
        def add_bytes(rel_arc: str, data: bytes) -> None:
            ti = tarfile.TarInfo(name=f"{top}/{rel_arc}")
            ti.size = len(data)
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(data))

        add_bytes("PKG-INFO", _metadata_bytes(name, version, summary, requires_python))

        seen: set[str] = set()
        for src, dst_rel in entries:
            if not src.exists():
                continue
            if src.is_file():
                rel_arc = dst_rel.strip("/")
                if rel_arc not in seen and rel_arc not in excluded:
                    seen.add(rel_arc)
                    tf.add(src, arcname=f"{top}/{rel_arc}")
            else:
                base_arc = dst_rel.strip("/")
                for p in sorted(src.rglob("*")):
                    if not p.is_file():
                        continue
                    rel = p.relative_to(src)
                    if _should_skip_sdist(rel):
                        continue
                    rel_arc = f"{base_arc}/{rel.as_posix()}" if base_arc else rel.as_posix()
                    if rel_arc not in seen and rel_arc not in excluded:
                        seen.add(rel_arc)
                        tf.add(p, arcname=f"{top}/{rel_arc}")

        if bundle_backend_as and bundle_backend_as not in seen:
            seen.add(bundle_backend_as)
            backend_src = Path(__file__).read_bytes()
            add_bytes(bundle_backend_as, backend_src)

    return tar_name


# PEP 517 hooks when invoked directly from repo root `pyproject.toml`.
def get_requires_for_build_wheel(config_settings=None):
    return []


def get_requires_for_build_sdist(config_settings=None):
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    root = Path.cwd().resolve()
    return prepare_metadata_for_project(root, metadata_directory)


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    root = Path.cwd().resolve()
    raw = os.environ.get("OUTSIDER_BUILD_TARGETS", "cli,relay")
    targets = [t.strip() for t in raw.split(",") if t.strip()]
    return build_wheel_for_targets(root, root, targets, wheel_directory)


def build_sdist(sdist_directory, config_settings=None):
    root = Path.cwd().resolve()
    names = [
        "pyproject.toml",
        "go.mod",
        "go.sum",
        "cli",
        "relay",
        "web",
        "protocol",
        "scripts/pep517_backend.py",
    ]
    return build_sdist_for_project(
        project_dir=root,
        entries=[(root / n, n) for n in names],
        sdist_directory=sdist_directory,
    )
