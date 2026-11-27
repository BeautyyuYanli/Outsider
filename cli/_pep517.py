from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_core():
    here = Path(__file__).resolve().parent
    for candidate in (here / "_pep517_core.py", here.parent / "scripts" / "pep517_backend.py"):
        if candidate.is_file():
            spec = importlib.util.spec_from_file_location("_outsider_pep517_core", candidate)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    raise RuntimeError("cannot locate outsider PEP 517 backend")


def _repo_root() -> Path:
    here = Path(__file__).resolve().parent
    if (here / "go.mod").is_file():
        return here
    if (here.parent / "go.mod").is_file():
        return here.parent
    return here


def get_requires_for_build_wheel(config_settings=None):
    return []


def get_requires_for_build_sdist(config_settings=None):
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    return _load_core().prepare_metadata_for_project(Path(__file__).resolve().parent, metadata_directory)


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    core = _load_core()
    here = Path(__file__).resolve().parent
    return core.build_wheel_for_targets(here, _repo_root(), ["cli"], wheel_directory)


def build_sdist(sdist_directory, config_settings=None):
    core = _load_core()
    here = Path(__file__).resolve().parent
    repo = _repo_root()
    entries = [
        (here / "pyproject.toml", "pyproject.toml"),
        (here / "_pep517.py", "_pep517.py"),
        (repo / "go.mod", "go.mod"),
        (repo / "go.sum", "go.sum"),
        (repo / "cmd" / "outsider", "cmd/outsider"),
        (repo / "internal" / "proto", "internal/proto"),
        (repo / "internal" / "sopsage", "internal/sopsage"),
        (repo / "internal" / "cli", "internal/cli"),
    ]
    return core.build_sdist_for_project(
        project_dir=here,
        entries=entries,
        sdist_directory=sdist_directory,
        bundle_backend_as="_pep517_core.py",
    )
