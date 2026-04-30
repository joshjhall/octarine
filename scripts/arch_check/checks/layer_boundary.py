"""Check 1: Layer 1 (primitives) must not import observe."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Iterator

from scripts.arch_check.core import Finding, rel


def run(*, files: Iterable[Path], root: Path) -> Iterator[Finding]:
    for path in files:
        # Bash: `if [[ "$file" == *"/primitives/"* ]]` is implicit because
        # the iterator is rooted at primitives/, but we filter explicitly here
        # so callers pass `iter_files(subdir="primitives", ...)`.
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if "use crate::observe" in line:
                yield Finding(
                    severity="ERROR",
                    check="layer-boundary",
                    rel_path=rel(path, root),
                    line=lineno,
                    message="observe imported in Layer 1 (primitives)",
                )
