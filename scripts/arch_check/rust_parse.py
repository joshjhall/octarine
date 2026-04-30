"""Rust `use` statement collapser.

Bash uses `perl -0777 -pe` to fold multi-line `pub(crate) use X::{\n A,\n B\n};`
into a single line so subsequent line-by-line greps see the full import set.
This module provides the equivalent in pure Python.
"""

from __future__ import annotations

import re
from typing import Literal

# Match `pub use ` or `pub(crate) use ` followed by anything up to the next `;`.
# `[^;]+` is greedy but bounded by `;`, so it captures one full statement.
_PUB_USE = re.compile(r"pub\s+use\s+[^;]+", re.MULTILINE)
_PUBCRATE_USE = re.compile(r"pub\(crate\)\s+use\s+[^;]+", re.MULTILINE)


def collapse_use_statements(text: str, *, kind: Literal["pub", "pubcrate"]) -> str:
    """Replace newlines inside matching `use` statements with single spaces.

    Content outside `use` statements is left untouched. Does not parse Rust;
    just folds line breaks within a `pub use ... ;` (or `pub(crate) use ... ;`)
    span. Matches the perl regex behavior in arch-check.sh.
    """
    pattern = _PUBCRATE_USE if kind == "pubcrate" else _PUB_USE
    return pattern.sub(lambda m: m.group(0).replace("\n", " "), text)
