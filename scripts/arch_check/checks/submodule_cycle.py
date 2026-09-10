"""Check: `primitives/data` must not import `primitives::identifiers`.

Layer 1's sub-modules have a documented one-way data flow: `identifiers → data`
(sanitizers compose redaction tokens from `data::tokens`). An import in the other
direction closes a cycle that Rust permits — both halves live in the same
`pub(crate)` bucket — but that blocks either sub-module from being extracted to
its own crate and makes ownership of shared types ambiguous.

Shared types belong in `primitives/types/` (the central definition location), to be
re-exported from whichever domain modules use them. See issue #404.

Matching covers every visibility form an import can take (`use`, `pub use`,
`pub(crate) use`, `pub(super) use`, …) and both absolute (`crate::primitives::
identifiers::…`) and relative (`super::super::identifiers::…`) paths — all of which
close the same cycle.

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
# identifiers::`) or relatively (`super::super::identifiers::`, `self::…`).
# A path segment boundary is required on the left so an unrelated module whose
# name merely ends in `identifiers` is not matched.
FORBIDDEN_PATH = re.compile(r"(?:^|::|\s)identifiers::")


def run(*, files: Iterable[Path], root: Path) -> Iterator[Finding]:
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel_path = rel(path, root)
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if not IMPORT_LINE.match(stripped):
                continue
            if not FORBIDDEN_PATH.search(stripped):
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
