"""Packaging guards: every source file the service uses must be in the repo.

`git add -A` silently skips ignored files and `git status` hides them, so a
source file can live in one working tree indefinitely while being absent from
every clone. That happened for real: `app/secrets.py` was matched by the
`secrets.*` ignore rule, so the full local test suite passed and the deployed
service died at import time with `No module named 'app.secrets'`.

These tests compare the filesystem against the git index, which is the only
place that can answer "will a fresh clone have this file?".
"""

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIRS = ("app", "tests", "tools", "static")
SOURCE_SUFFIXES = {".py", ".html", ".js", ".css"}


def _tracked():
    """Paths under SOURCE_DIRS that are in the git index."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z", *SOURCE_DIRS],
            cwd=ROOT,
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        pytest.skip(f"not a usable git checkout: {exc}")
    return {p for p in result.stdout.decode().split("\0") if p}


def _present():
    """Source files that exist on disk right now."""
    found = set()
    for directory in SOURCE_DIRS:
        for path in (ROOT / directory).rglob("*"):
            if not path.is_file():
                continue
            if {"__pycache__", ".pytest_cache"} & set(path.parts):
                continue
            if path.suffix in SOURCE_SUFFIXES:
                found.add(path.relative_to(ROOT).as_posix())
    return found


def test_every_source_file_is_tracked():
    missing = sorted(_present() - _tracked())
    assert not missing, (
        "these source files exist locally but are not in the repository, so a "
        f"fresh clone will be broken: {missing}"
    )


def test_secrets_module_is_importable():
    """The module that loads the signing seed must exist in every checkout."""
    from app import secrets

    assert callable(secrets.load_seed)
    assert callable(secrets.load_public_key)
    assert callable(secrets.seed_problem)
