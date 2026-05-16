"""Check 8: File length — production LOC must not exceed 800.

Production LOC is total file LOC minus everything from the first
`#[cfg(test)]` module onward. Files may opt out with an explicit
`// arch-check: allow file-length` waiver comment within the first 20 lines.

Mirrors the size-limit policy in `CLAUDE.md`:

    Preferred: <300 LOC per file
    Warning:   >500 LOC
    Split at:  >800 LOC

Only the >800 split threshold is enforced here. The other thresholds are
advisory guidance that may be revisited as the codebase evolves.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from scripts.arch_check.core import Finding, iter_files, rel

_PROD_LOC_LIMIT = 800
_WAIVER_WINDOW = 20
_WAIVER_MARKER = "arch-check: allow file-length"
_TEST_MODULE_MARKER = "#[cfg(test)]"


def _production_loc(text: str) -> int:
    """Return production LOC = total lines minus inline test module.

    The first ``#[cfg(test)]`` line and everything after it is excluded.
    If no test module is present, the whole file is production.
    """
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if line.lstrip().startswith(_TEST_MODULE_MARKER):
            return idx
    return len(lines)


def _has_waiver(text: str) -> bool:
    """Detect the inline waiver comment in the first 20 lines."""
    for line in text.splitlines()[:_WAIVER_WINDOW]:
        if _WAIVER_MARKER in line:
            return True
    return False


def run(*, staged_only: bool, root: Path) -> Iterator[Finding]:
    for path in iter_files(subdir=None, staged_only=staged_only, root=root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _has_waiver(text):
            continue
        prod = _production_loc(text)
        if prod > _PROD_LOC_LIMIT:
            yield Finding(
                severity="ERROR",
                check="file-length",
                rel_path=rel(path, root),
                line=None,
                message=(
                    f"file has {prod} production LOC; split at >{_PROD_LOC_LIMIT} "
                    f"(or add `// {_WAIVER_MARKER}` near the top with justification)"
                ),
            )
