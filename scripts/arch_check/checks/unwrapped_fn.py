"""Check 2: L3 must not re-export primitives functions.

Multi-line `pub use crate::primitives::X::{ A, B };` blocks are folded into
a single line via `collapse_use_statements` so the inner regex sees the full
import set. Intentional bare re-exports can opt out with an inline directive
(see `_DIRECTIVE`).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from scripts.arch_check.core import Finding, rel
from scripts.arch_check.rust_parse import collapse_use_statements

_LINE_TRIGGER = "pub use crate::primitives::"
_INNER = re.compile(r"[{,]\s*[a-z][a-z0-9_]*")
_DIRECTIVE = re.compile(r"//\s*arch-check:\s*allow\s+unwrapped-fn\b")


def run(*, files: Iterable[Path], root: Path) -> Iterator[Finding]:
    for path in files:
        if "/primitives/" in str(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        text = collapse_use_statements(text, kind="pub")
        prev_nonblank = ""
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if _LINE_TRIGGER not in line:
                if stripped:
                    prev_nonblank = line
                continue
            if not _INNER.search(line):
                if stripped:
                    prev_nonblank = line
                continue
            if _DIRECTIVE.search(line) or _DIRECTIVE.search(prev_nonblank):
                if stripped:
                    prev_nonblank = line
                continue
            yield Finding(
                severity="WARN",
                check="unwrapped-fn",
                rel_path=rel(path, root),
                line=lineno,
                message="possible bare function re-export from primitives",
            )
            if stripped:
                prev_nonblank = line
