"""Shared fixtures for release helper tests."""

from __future__ import annotations

import sys
from pathlib import Path

# Make the repo root importable so `import scripts.release.*` works whether
# pytest is invoked from the repo root or any subdirectory.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
