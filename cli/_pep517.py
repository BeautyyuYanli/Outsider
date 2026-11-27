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


def get_requires_for_build_wheel(config_settings=None):
    return []


def get_requires_for_build_sdist(config_settings=None):
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    return _load_core().prepare_metadata_for_project(Path(__file__).resolve().parent, metadata_directory)


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    core = _load_core()
    here = Path(__file__).resolve().parent
    return core.build_wheel_for_targets(here, here, ["cli"], wheel_directory)


def build_sdist(sdist_directory, config_settings=None):
    core = _load_core()
    here = Path(__file__).resolve().parent
    entries = [
        (here / "pyproject.toml", "pyproject.toml"),
        (here / "_pep517.py", "_pep517.py"),
        (here / "Cargo.toml", "Cargo.toml"),
        (here / "Cargo.lock", "Cargo.lock"),
        (here / "src", "src"),
    ]
    return core.build_sdist_for_project(
        project_dir=here,
        entries=entries,
        sdist_directory=sdist_directory,
        bundle_backend_as="_pep517_core.py",
    )
