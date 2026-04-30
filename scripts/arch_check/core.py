"""Core types and file-iteration helpers for arch-check.

Mirrors the bash `files_to_check()` semantics from `scripts/arch-check.sh`
(lines 48-70), including the `--staged-only` git-diff path.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Literal


Severity = Literal["ERROR", "WARN"]


@dataclass(frozen=True)
class Finding:
    severity: Severity
    check: str
    rel_path: str
    message: str
    line: int | None = None


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def src_dir(root: Path | None = None) -> Path:
    return (root or repo_root()) / "crates" / "octarine" / "src"


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def format_finding(f: Finding) -> str:
    # Check 6 (type-visibility) omits the :line suffix; all others include it.
    # Bash uses two spaces after `[WARN]` for column alignment with `[ERROR]`.
    prefix = "[ERROR]" if f.severity == "ERROR" else "[WARN] "
    location = f.rel_path if f.line is None else f"{f.rel_path}:{f.line}"
    return f"{prefix} {f.check}: {location} -- {f.message}"


def git_staged_rs_files(root: Path) -> list[Path]:
    """Return absolute paths of staged .rs files (ACMR diff filter).

    Outside a git repo or with no staged files, returns an empty list —
    mirrors the bash `2>/dev/null || true` pattern.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            capture_output=True,
            text=True,
            check=False,
        )
    except (FileNotFoundError, OSError):
        return []
    if result.returncode != 0:
        return []
    files: list[Path] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.endswith(".rs"):
            files.append(root / line)
    return files


def iter_files(
    *,
    subdir: str | None,
    staged_only: bool,
    root: Path,
) -> Iterator[Path]:
    """Yield .rs files under `subdir` (or all of src/), respecting --staged-only.

    Mirrors bash `files_to_check()`. Sorted output for determinism.
    """
    base = src_dir(root)
    if subdir:
        base = base / subdir
    if not base.is_dir():
        return

    if staged_only:
        for path in git_staged_rs_files(root):
            try:
                path.relative_to(base)
            except ValueError:
                continue
            yield path
    else:
        for path in sorted(base.rglob("*.rs")):
            if path.is_file():
                yield path


def collect_findings(check_runner: Iterable[Finding]) -> list[Finding]:
    return list(check_runner)
