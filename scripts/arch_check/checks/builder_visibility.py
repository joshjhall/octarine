"""Check 7: Builders/functions in primitives must be `pub(crate) use`.

Business logic (builders, functions) in primitives aggregator mod.rs files
should use `pub(crate) use` so users go through L3 observe wrappers. Types
are allowed as `pub use` since they carry no logic.

File scope is a single-level glob:
  - $SRC/primitives/mod.rs
  - $SRC/primitives/*/mod.rs
Does NOT recurse into deeper subdirectories. `--staged-only` is ignored here
(matches bash). Multi-line `use` statements are NOT collapsed for this check
(matches bash).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from scripts.arch_check.core import Finding, rel, src_dir

_BUILDER = re.compile(r"\b[A-Z][a-zA-Z0-9]*Builder\b")
_LOWER_TOKEN = re.compile(r"\b[a-z][a-z0-9_]+\b")
_KEYWORDS = frozenset({"self", "super", "crate", "as", "use", "pub", "mod"})
_COMMENT = re.compile(r"^\s*//")


def _candidate_files(root: Path) -> list[Path]:
    src = src_dir(root)
    primitives = src / "primitives"
    candidates: list[Path] = []
    top = primitives / "mod.rs"
    if top.is_file():
        candidates.append(top)
    if primitives.is_dir():
        for child in sorted(primitives.iterdir()):
            if child.is_dir():
                modfile = child / "mod.rs"
                if modfile.is_file():
                    candidates.append(modfile)
    return candidates


def run(*, root: Path) -> Iterator[Finding]:
    for modfile in _candidate_files(root):
        try:
            text = modfile.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if "pub use" not in line:
                continue
            if "pub(crate)" in line:
                continue
            if _COMMENT.match(line):
                continue

            for name in _BUILDER.findall(line):
                yield Finding(
                    severity="WARN",
                    check="builder-visibility",
                    rel_path=rel(modfile, root),
                    line=lineno,
                    message=(
                        f"'{name}' should use pub(crate) use in primitives "
                        "(business logic must go through L3 wrappers)"
                    ),
                )

            if "{" in line:
                start = line.index("{") + 1
                end = line.rfind("}")
                if end == -1:
                    end = len(line)
                inner = line[start:end]
                for fn_name in _LOWER_TOKEN.findall(inner):
                    if fn_name in _KEYWORDS:
                        continue
                    yield Finding(
                        severity="WARN",
                        check="builder-visibility",
                        rel_path=rel(modfile, root),
                        line=lineno,
                        message=f"'{fn_name}' (function) should use pub(crate) use in primitives",
                    )
