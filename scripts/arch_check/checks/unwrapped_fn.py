"""Check 2: L3 must not re-export primitives functions.

Parity note (preserved bash behavior):
The bash version greps line-by-line for `pub use crate::primitives::`, so it
only sees the head line of multi-line `pub use crate::primitives::X::{\n A,\n
B\n};` blocks. The inner regex `[{,]\\s*[a-z][a-z0-9_]*` does not match that
head line, so multi-line blocks are silently skipped. We preserve this
behavior verbatim for byte-identical output. Track a fix in a separate
follow-up issue.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from scripts.arch_check.core import Finding, rel

_LINE_TRIGGER = "pub use crate::primitives::"
_INNER = re.compile(r"[{,]\s*[a-z][a-z0-9_]*")


def run(*, files: Iterable[Path], root: Path) -> Iterator[Finding]:
    for path in files:
        if "/primitives/" in str(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _LINE_TRIGGER not in line:
                continue
            if _INNER.search(line):
                yield Finding(
                    severity="WARN",
                    check="unwrapped-fn",
                    rel_path=rel(path, root),
                    line=lineno,
                    message="possible bare function re-export from primitives",
                )
