"""Check 6: Types re-exported by L3 must be `pub use` in primitives.

If L3 does `pub use crate::primitives::X::Y` for a type, then Y must be
`pub use` (not `pub(crate) use`) in the primitives module — otherwise rustc
rejects with E0365. Catches the mismatch before compile.

Output format note: this check emits NO `:line` suffix. The format is
`type-visibility: <rel> -- '<name>' is pub(crate) in primitives but L3 tries
pub use at <other_rel>`.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from scripts.arch_check.core import Finding, iter_files, rel, src_dir
from scripts.arch_check.rust_parse import collapse_use_statements

_PASCAL = re.compile(r"\b[A-Z][a-zA-Z0-9]+\b")
_BUILDER_SUFFIX = re.compile(r"Builder$")


def _extract_pascal_non_builder(line: str) -> list[str]:
    return [n for n in _PASCAL.findall(line) if not _BUILDER_SUFFIX.search(n)]


def run(*, staged_only: bool, root: Path) -> Iterator[Finding]:
    src = src_dir(root)
    primitives = src / "primitives"

    pubcrate_types: dict[str, str] = {}
    if primitives.is_dir():
        for modfile in sorted(primitives.rglob("mod.rs")):
            try:
                text = modfile.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            collapsed = collapse_use_statements(text, kind="pubcrate")
            for line in collapsed.splitlines():
                if "pub(crate) use" not in line:
                    continue
                for name in _extract_pascal_non_builder(line):
                    pubcrate_types[name] = rel(modfile, root)

    l3_pub_types: dict[str, str] = {}
    for path in iter_files(subdir=None, staged_only=staged_only, root=root):
        if "/primitives/" in str(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        collapsed = collapse_use_statements(text, kind="pub")
        for line in collapsed.splitlines():
            if "pub use crate::primitives::" not in line:
                continue
            for name in _extract_pascal_non_builder(line):
                l3_pub_types[name] = rel(path, root)

    # Sorted for determinism (bash hash iteration is undefined).
    for name in sorted(pubcrate_types):
        if name in l3_pub_types:
            yield Finding(
                severity="ERROR",
                check="type-visibility",
                rel_path=pubcrate_types[name],
                line=None,
                message=(
                    f"'{name}' is pub(crate) in primitives but L3 tries "
                    f"pub use at {l3_pub_types[name]}"
                ),
            )
