"""Check 4: Return type vs prefix mismatches in identifier modules.

Two passes per file in this order:
  1. `is_*` returning Option/Result/Vec/String  -> WARN
  2. `validate_*` returning bool                -> WARN

Order matters for byte-identical output: bash runs both regex passes per file
in this same order before moving to the next file.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from scripts.arch_check.core import Finding, iter_files, rel

_IS_PATTERN = re.compile(r"pub fn is_[a-z_]+\(.*\)\s*->\s*(Option|Result|Vec|String)")
_VALIDATE_PATTERN = re.compile(r"pub fn validate_[a-z_]+\(.*\)\s*->\s*bool")


def run(*, staged_only: bool, root: Path) -> Iterator[Finding]:
    for subdir in ("primitives/identifiers", "identifiers"):
        for path in iter_files(subdir=subdir, staged_only=staged_only, root=root):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lines = list(enumerate(text.splitlines(), start=1))
            for lineno, line in lines:
                if _IS_PATTERN.search(line):
                    yield Finding(
                        severity="WARN",
                        check="naming-return-type",
                        rel_path=rel(path, root),
                        line=lineno,
                        message="is_* should return bool",
                    )
            for lineno, line in lines:
                if _VALIDATE_PATTERN.search(line):
                    yield Finding(
                        severity="WARN",
                        check="naming-return-type",
                        rel_path=rel(path, root),
                        line=lineno,
                        message="validate_* should return Result",
                    )
