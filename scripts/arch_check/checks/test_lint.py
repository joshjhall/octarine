"""Check 5: Tests must not allow indexing_slicing."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from scripts.arch_check.core import Finding, rel

_PATTERN = re.compile(r"allow.*clippy::indexing_slicing")


def run(*, files: Iterable[Path], root: Path) -> Iterator[Finding]:
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _PATTERN.search(line):
                yield Finding(
                    severity="ERROR",
                    check="test-lint",
                    rel_path=rel(path, root),
                    line=lineno,
                    message="indexing_slicing must not be allowed (use .get()/.first()/.last())",
                )
