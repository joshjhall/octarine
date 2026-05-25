"""Check: unexplained ```ignore on public-API doctests (Layer 2/3 only).

A doctest fence annotated with ```ignore (or ```rust,ignore) silently opts
out of compilation. Without a justification comment, a reader cannot tell
whether the example "won't compile," "shouldn't run in CI," or "the author
hadn't decided yet."

Rule: in any Layer 2/3 file (not `/primitives/`, not `/testing/`), an
```ignore fence must be accompanied by an explanatory comment within the
preceding 3 lines, OR carry an `// arch-check: allow doctest-ignores`
directive (mirrors `unwrapped_fn.py`).

A justification comment is any preceding line whose comment body contains
the substring `ignore` (case-insensitive) — e.g.
``/// Requires a tokio runtime — ignored because async I/O``.
This is intentionally generous: the goal is to force authors to write
*something*, not to police phrasing.

This check is part of the default gating set (ERROR severity); a new
unjustified ```ignore fence will fail `just arch-check` and CI. See
`docs/development/doctest-fences.md` for the ignore vs no_run vs plain
rust decision guide.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from scripts.arch_check.core import Finding, rel

# Matches: optional indent, doc-comment prefix, ```ignore or ```rust,ignore
_IGNORE_FENCE = re.compile(r"^\s*//[!/] *```(?:rust,)?ignore\s*$")

# Any comment line — doc (`///`, `//!`) or plain (`//`). Used to scan back
# through a contiguous comment block. Blank lines are also tolerated.
_COMMENT_LINE = re.compile(r"^\s*//")

# Suppression directive (mirrors unwrapped_fn.py convention)
_DIRECTIVE = re.compile(r"//\s*arch-check:\s*allow\s+doctest-ignores\b")

# How many preceding comment lines we scan for a justification
_LOOKBACK = 3


def _has_justification(prev_lines: list[str]) -> bool:
    """True if any recent comment line justifies the ignore."""
    for line in prev_lines:
        if _DIRECTIVE.search(line):
            return True
        # Doc comment whose text mentions "ignore" counts as justification.
        # Strip the prefix so the fence's own `///` doesn't satisfy itself.
        stripped = line.lstrip()
        if stripped.startswith("///"):
            body = stripped[3:]
        elif stripped.startswith("//!"):
            body = stripped[3:]
        else:
            # Plain `//` comment — only directive (handled above) suppresses.
            continue
        if "ignore" in body.lower():
            return True
    return False


def run(*, files: Iterable[Path], root: Path) -> Iterator[Finding]:
    for path in files:
        path_str = str(path)
        if "/primitives/" in path_str or "/testing/" in path_str:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        lines = text.splitlines()
        # Window of the most recent comment lines (doc or plain). A code
        # line resets it so a fence cannot inherit justification from a
        # different item upstream.
        comment_window: list[str] = []
        for lineno, line in enumerate(lines, start=1):
            if _IGNORE_FENCE.match(line):
                recent = comment_window[-_LOOKBACK:]
                if not _has_justification(recent):
                    yield Finding(
                        severity="ERROR",
                        check="doctest-ignores",
                        rel_path=rel(path, root),
                        line=lineno,
                        message=(
                            "unexplained ```ignore on doctest; add a "
                            "justification comment or use ```no_run / "
                            "plain ```rust if the example can run"
                        ),
                    )
                comment_window.append(line)
            elif _COMMENT_LINE.match(line):
                comment_window.append(line)
            elif not line.strip():
                # Blank lines neither contribute nor reset.
                continue
            else:
                comment_window = []
