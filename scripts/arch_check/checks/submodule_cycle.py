"""Check: `primitives/data` must not import `primitives::identifiers`.

Layer 1's sub-modules have a documented one-way data flow: `identifiers → data`
(sanitizers compose redaction tokens from `data::tokens`). An import in the other
direction closes a cycle that Rust permits — both halves live in the same
`pub(crate)` bucket — but that blocks either sub-module from being extracted to
its own crate and makes ownership of shared types ambiguous.

Shared types belong in `primitives/types/` (the central definition location), to be
re-exported from whichever domain modules use them. See issue #404.

Matching covers every visibility form an import can take (`use`, `pub use`,
`pub(crate) use`, `pub(super) use`, …), both absolute (`crate::primitives::
identifiers::…`) and relative (`super::super::identifiers::…`) paths, and
brace-grouped imports in both their single-line and multi-line (rustfmt-produced)
spellings — all of which close the same cycle. Each `use` statement is joined to
its terminating `;` before matching, so a forbidden segment on a continuation line
is still seen.

Known limitation: only *import* lines are inspected. A fully-qualified inline call —
`crate::primitives::identifiers::network::…::new().is_uuid(x)` — closes the same
cycle without an import line and is NOT caught. One such call currently exists at
`primitives/data/network/url.rs`; extending this check to qualified paths is tracked
in issue #753.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from scripts.arch_check.core import Finding, rel

# Any visibility form of an import: `use`, `pub use`, `pub(crate) use`,
# `pub(super) use`, `pub(in path) use`. Anchored so it only matches import
# statements, never a mid-expression occurrence.
IMPORT_LINE = re.compile(r"^(?:pub\s*(?:\([^)]*\)\s*)?)?use\s")

# The identifiers sub-module reached either absolutely (`crate::primitives::
# identifiers::`) or relatively (`super::super::identifiers::`, `self::…`), or as a
# member of a brace group (`primitives::{identifiers::crypto::KeyType, …}`).
# A path-segment boundary is required on the left so an unrelated module whose
# name merely ends in `identifiers` (`my_identifiers::`) is not matched.
FORBIDDEN_PATH = re.compile(r"(?:^|::|[{,\s])identifiers::")


def _strip_line_comment(line: str) -> str:
    """Drop a trailing `//` comment.

    The terminator search must not see a `;` that belongs to a comment — e.g.
    `types::Problem, // keep sorted; see mod.rs` — or the join stops early and
    the rest of the brace group (which may hold the forbidden segment) is never
    examined. Block comments spanning a `;` remain unhandled; they do not occur
    inside import statements in this tree.
    """
    head, _, _ = line.partition("//")
    return head


def _iter_use_statements(text: str) -> Iterator[tuple[int, str]]:
    """Yield (line number of the `use` keyword, whole statement) for each import.

    A `use` statement is joined across lines until its terminating `;`, so a
    brace-grouped import spanning several lines is matched as one unit rather
    than as fragments that individually satisfy neither pattern.
    """
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        stripped = lines[index].lstrip()
        if not IMPORT_LINE.match(stripped):
            index += 1
            continue
        start = index
        parts = [_strip_line_comment(stripped)]
        # Join continuation lines until the statement terminates. Bounded by the
        # end of file, so an unterminated statement cannot loop forever.
        while ";" not in parts[-1] and index + 1 < len(lines):
            index += 1
            parts.append(_strip_line_comment(lines[index].strip()))
        yield start + 1, " ".join(parts)
        index += 1


def run(*, files: Iterable[Path], root: Path) -> Iterator[Finding]:
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel_path = rel(path, root)
        for lineno, statement in _iter_use_statements(text):
            if not FORBIDDEN_PATH.search(statement):
                continue
            yield Finding(
                severity="ERROR",
                check="submodule-cycle",
                rel_path=rel_path,
                line=lineno,
                message=(
                    "identifiers imported from primitives/data "
                    "(closes a Layer 1 cycle — move shared types to primitives/types)"
                ),
            )
