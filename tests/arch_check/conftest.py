"""Shared fixtures for arch_check tests."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Callable

import pytest

# Make the repo root importable so `import scripts.arch_check.*` works whether
# pytest is invoked from the repo root or any subdirectory.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_path() -> Callable[[str, str], Path]:
    def _get(check_name: str, file_name: str) -> Path:
        path = FIXTURES / check_name / file_name
        if not path.exists():
            pytest.fail(f"fixture not found: {path}")
        return path

    return _get


@pytest.fixture
def fixtures_root() -> Path:
    return FIXTURES


@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    """Build a synthetic repo layout: tmp_path/crates/octarine/src/.

    Returns the tmp repo root (not the src dir). Writers append files under
    the returned root using `crates/octarine/src/...` paths to mirror the
    real layout.
    """
    src = tmp_path / "crates" / "octarine" / "src"
    src.mkdir(parents=True, exist_ok=True)
    return tmp_path


@pytest.fixture
def write_rs(tmp_repo: Path) -> Callable[[str, str], Path]:
    """Write a .rs file under tmp_repo/crates/octarine/src/<rel>."""

    def _write(rel: str, content: str) -> Path:
        target = tmp_repo / "crates" / "octarine" / "src" / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    return _write
