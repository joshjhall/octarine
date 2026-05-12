"""Check 3: Prohibited naming prefixes in identifier modules."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from scripts.arch_check.core import Finding, iter_files, rel

_TRIGGER = re.compile(r"pub fn (has_|contains_|check_|verify_|ensure_|remove_)")
_EXTRACT = re.compile(r"(has_|contains_|check_|verify_|ensure_|remove_)[a-z_]*")

# Subdirs to scan. Order matches the historical bash recipe: identifier
# subdirs first, then the broader primitives/observe domains added in #193,
# then Layer 3 modules added in #314.
_SUBDIRS: tuple[str, ...] = (
    "primitives/identifiers",
    "identifiers",
    "primitives/crypto",
    "primitives/data",
    "primitives/io",
    "observe",
    "crypto",
    "data",
    "security",
    "auth",
    "http",
    "runtime",
    "io",
)


def run(*, staged_only: bool, root: Path) -> Iterator[Finding]:
    for subdir in _SUBDIRS:
        for path in iter_files(subdir=subdir, staged_only=staged_only, root=root):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if not _TRIGGER.search(line):
                    continue
                m = _EXTRACT.search(line)
                fn_name = m.group(0) if m else ""
                yield Finding(
                    severity="ERROR",
                    check="naming-prefix",
                    rel_path=rel(path, root),
                    line=lineno,
                    message=f"prohibited prefix in '{fn_name}'",
                )
