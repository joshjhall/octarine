"""Check 3: Prohibited naming prefixes in identifier modules."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from scripts.arch_check.core import Finding, iter_files, rel

_TRIGGER = re.compile(r"pub fn (has_|contains_|check_|verify_|ensure_|remove_)")
_EXTRACT = re.compile(r"(has_|contains_|check_|verify_|ensure_|remove_)[a-z_]*")


def run(*, staged_only: bool, root: Path) -> Iterator[Finding]:
    # Subdir order matches bash: primitives/identifiers first, then identifiers.
    for subdir in ("primitives/identifiers", "identifiers"):
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
