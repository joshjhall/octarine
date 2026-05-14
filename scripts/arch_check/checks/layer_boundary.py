"""Check 1: Layer 1 (primitives) must not import observe.

Allowance: `primitives/types/mod.rs` may `pub use crate::observe::*` to
re-export observability-enabled trait facades (e.g., `ProblemExt`). These
re-exports are façades for downstream consumers, not logic dependencies of
primitives code itself. Primitives module bodies must still not pull
observe items into scope for direct use.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Iterator

from scripts.arch_check.core import Finding, rel


def run(*, files: Iterable[Path], root: Path) -> Iterator[Finding]:
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel_path = rel(path, root)
        is_types_mod = rel_path.endswith("primitives/types/mod.rs")
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if "use crate::observe" not in stripped:
                continue
            # Allow `pub use crate::observe::...;` re-exports from the central
            # type-bridge module. These are façade re-exports, not internal
            # observe dependencies.
            if is_types_mod and stripped.startswith("pub use crate::observe"):
                continue
            yield Finding(
                severity="ERROR",
                check="layer-boundary",
                rel_path=rel_path,
                line=lineno,
                message="observe imported in Layer 1 (primitives)",
            )
