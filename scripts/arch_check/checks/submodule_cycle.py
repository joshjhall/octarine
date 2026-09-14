"""Check: `primitives/data` must not import `primitives::identifiers`.

Layer 1's sub-modules have a documented one-way data flow: `identifiers → data`
(sanitizers compose redaction tokens from `data::tokens`). An import in the other
direction closes a cycle that Rust permits — both halves live in the same
`pub(crate)` bucket — but that blocks either sub-module from being extracted to
its own crate and makes ownership of shared types ambiguous.

Shared types belong in `primitives/types/` (the central definition location), to be
re-exported from whichever domain modules use them. See issue #404.

Matching covers every visibility form an import can take (`use`, `pub use`,
`pub(crate) use`, `pub(super) use`, …), both absolute (`crate::primitives::
identifiers::…`) and relative (`super::super::identifiers::…`) paths, and
brace-grouped imports in both their single-line and multi-line (rustfmt-produced)
spellings, and bare (`use …::identifiers;`) or aliased (`… as ids;`) module
imports — all of which close the same cycle. Each `use` statement is joined to its
terminating `;` before matching, over text whose comments and string literals have
been blanked, so neither a forbidden segment on a continuation line nor a `;`
inside a comment can hide it.

Fully-qualified inline calls are covered too (issue #753). A call like
`crate::primitives::identifiers::network::…::new().is_uuid(x)` closes the same cycle
without any import line, so a second pass scans non-import code for a *rooted* path
into the module — `crate::primitives::identifiers::…` or `super::…::identifiers::…`.

Only rooted spellings need matching inline: an unrooted `identifiers::foo()` can only
resolve through an import, which the import pass above already rejects. Requiring a
root also keeps the inline rule from firing on unrelated text. Comments and string
literals are blanked before this pass — `primitives/data/mod.rs` and
`primitives/data/network/mod.rs` both name `primitives::identifiers` in module docs,
describing the legitimate `identifiers → data` direction, and those must not be
findings. Both span kinds are consumed by a single left-to-right scan
(`_blank_noncode`), because a string can contain `//` and a comment can contain a
quote; handling them in two ordered passes lets whichever runs first misread the
other's delimiters.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from pathlib import Path
from typing import Iterable, Iterator

from scripts.arch_check.core import Finding, rel

# Any visibility form of an import: `use`, `pub use`, `pub(crate) use`,
# `pub(super) use`, `pub(in path) use`. Anchored so it only matches import
# statements, never a mid-expression occurrence.
IMPORT_LINE = re.compile(r"^(?:pub\s*(?:\([^)]*\)\s*)?)?use\s")

# The identifiers sub-module reached either absolutely (`crate::primitives::
# identifiers::`) or relatively (`super::super::identifiers::`, `self::…`), or as a
# member of a brace group (`primitives::{identifiers::crypto::KeyType, …}`).
# A path-segment boundary is required on the left so an unrelated module whose
# name merely ends in `identifiers` (`my_identifiers::`) is not matched.
# The trailing context accepts `::` (a path continues), `;` / `}` / `,` (a bare
# module import, possibly inside a group), or ` as ` (an aliased one) — the last
# two import the module whole and close the cycle just as surely.
# The left boundary requires `::` for the bare/aliased forms, so aliasing an
# unrelated import TO this name (`use …::helper as identifiers;`) is not matched:
# that introduces no dependency on the identifiers module.
FORBIDDEN_PATH = re.compile(
    r"(?:^|::|[{,\s])identifiers::"  # a path continues past the segment
    r"|(?:::|[{,])\s*identifiers\s*(?:[;,}]|\s+as\s)"  # bare or aliased module
)


# A fully-qualified inline path into the module, reached from a root: `crate::` for
# an absolute path, or one or more `super::` hops for a relative one. Unrooted
# `identifiers::…` needs an import to resolve, and the import pass already covers
# that, so requiring a root here costs no coverage and avoids matching stray text.
# Whitespace is permitted after every `::` so a path rustfmt wrapped across any
# number of lines still matches as one unit. This is why the scan runs over the
# whole blanked text rather than line by line — a line-local match could only ever
# see one fragment of a wrapped path.
QUALIFIED_PATH = re.compile(
    r"(?:^|[^A-Za-z0-9_])"  # not mid-identifier (`my_crate::…` must not match)
    r"((?:crate|(?:super::\s*)*super)::\s*"  # group 1 starts at the root token
    r"(?:[A-Za-z_][A-Za-z0-9_]*::\s*)*?"  # intervening segments (`primitives::`, …)
    r"identifiers::)"
)

# Token starts that must be consumed as a unit by `_blank_noncode`, longest-prefix
# first so `r#"` is tried before `r"` and `/*` before `/`.
_RAW_STRING_OPEN = re.compile(r'r(#*)"')


def _blank_noncode(text: str) -> str:
    """Blank every comment and string/char literal, in a single left-to-right pass.

    Both kinds of span must be recognized in the order they actually appear,
    because each can contain the other's opening delimiter:

    - a string holding `//` or `/*` (`"http://example.com"`) is NOT a comment,
    - a comment holding a quote (`// it's fine`) does NOT open a string.

    Two independent regex passes cannot express that — whichever runs first wins,
    and the loser's delimiters get misread. Stripping comments first (the original
    ordering) truncated a line at the `//` inside a URL string and silently dropped
    any forbidden path after it on that line, a false negative in the very check
    this module provides. A single cursor that consumes whichever span opens next
    has no such ordering to get wrong.

    Content is replaced with spaces and newlines are preserved, so both line
    numbers and column positions survive. The `;` that terminates a `use`
    statement is likewise protected, which is what lets `_iter_use_statements`
    join a brace group without stopping at a `;` inside a trailing comment.
    """
    out: list[str] = []
    index = 0
    length = len(text)

    def blank_span(span: str) -> str:
        # Keep newlines (line numbers) and width (column positions).
        return "".join("\n" if char == "\n" else " " for char in span)

    while index < length:
        char = text[index]

        # Line comment: runs to the end of the line (the newline itself is code).
        if text.startswith("//", index):
            end = text.find("\n", index)
            end = length if end == -1 else end
            out.append(blank_span(text[index:end]))
            index = end
            continue

        # Block comment: Rust nests these, so track depth rather than stopping at
        # the first `*/`.
        if text.startswith("/*", index):
            depth = 1
            scan = index + 2
            while scan < length and depth:
                if text.startswith("/*", scan):
                    depth += 1
                    scan += 2
                elif text.startswith("*/", scan):
                    depth -= 1
                    scan += 2
                else:
                    scan += 1
            out.append(blank_span(text[index:scan]))
            index = scan
            continue

        # Raw string: `r"…"`, `r#"…"#`, `r##"…"##`. No escapes; the terminator is
        # a quote followed by exactly as many `#` as the opener carried.
        raw = _RAW_STRING_OPEN.match(text, index)
        if raw:
            terminator = '"' + raw.group(1)
            end = text.find(terminator, raw.end())
            end = length if end == -1 else end + len(terminator)
            out.append(blank_span(text[index:end]))
            index = end
            continue

        # Ordinary string or char literal, honouring backslash escapes. A char
        # literal and a lifetime (`'a`) share a leading quote, so a `'` that never
        # closes is treated as code rather than swallowing the rest of the file.
        if char in "\"'":
            scan = index + 1
            while scan < length:
                if text[scan] == "\\":
                    scan += 2
                    continue
                if text[scan] == char:
                    break
                if char == "'" and text[scan] == "\n":
                    # Unterminated on this line: a lifetime, not a char literal.
                    scan = index
                    break
                scan += 1
            if scan == index:
                out.append(char)
                index += 1
                continue
            end = min(scan + 1, length)
            out.append(blank_span(text[index:end]))
            index = end
            continue

        out.append(char)
        index += 1

    return "".join(out)




def _iter_use_statements(text: str) -> Iterator[tuple[int, int, str]]:
    """Yield (first line, last line, whole statement) for each import.

    A `use` statement is joined across lines until its terminating `;`, so a
    brace-grouped import spanning several lines is matched as one unit rather
    than as fragments that individually satisfy neither pattern. Both line numbers
    are reported because the joined text no longer carries its own newlines: the
    inline pass needs the full span to know which lines an import already covers.
    """
    lines = _blank_noncode(text).splitlines()
    index = 0
    while index < len(lines):
        stripped = lines[index].lstrip()
        if not IMPORT_LINE.match(stripped):
            index += 1
            continue
        start = index
        parts = [stripped]
        # Join continuation lines until the statement terminates. Bounded by the
        # end of file, so an unterminated statement cannot loop forever.
        while ";" not in parts[-1] and index + 1 < len(lines):
            index += 1
            parts.append(lines[index].strip())
        yield start + 1, index + 1, " ".join(parts)
        index += 1


REMEDY = "(closes a Layer 1 cycle — move shared code to primitives/types)"


def _iter_qualified_lines(text: str, skip: set[int]) -> Iterator[int]:
    """Yield line numbers holding a rooted qualified path outside an import.

    `skip` carries the lines the import pass already reported, so an offending
    `use` statement — which is also a qualified path — is reported once, as an
    import, with the more specific message.

    The scan runs over the **whole** blanked text rather than line by line, and
    `QUALIFIED_PATH` tolerates whitespace after each `::`. A path that rustfmt
    wrapped across any number of lines is therefore matched as one unit —
    line-local matching could only ever see one fragment of it, and a violation
    could hide behind a line break. Each match is reported against the line its
    root starts on.
    """
    blanked = _blank_noncode(text)
    # Prefix lengths, so a match offset can be turned back into a line number.
    line_starts = [0]
    for index, character in enumerate(blanked):
        if character == "\n":
            line_starts.append(index + 1)

    for match in QUALIFIED_PATH.finditer(blanked):
        # Group 1 starts at the root token itself, past the boundary character the
        # pattern opens with, so this is the position to report.
        lineno = bisect_right(line_starts, match.start(1))
        if lineno not in skip:
            yield lineno


def run(*, files: Iterable[Path], root: Path) -> Iterator[Finding]:
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel_path = rel(path, root)

        # Pass 1 — imports. Statements are joined across lines, so record every
        # line a reported statement spans; the inline pass must not re-report any
        # of them.
        import_lines: set[int] = set()
        findings: list[Finding] = []
        for lineno, end_lineno, statement in _iter_use_statements(text):
            if not FORBIDDEN_PATH.search(statement):
                continue
            # A joined statement occupies `lineno` through its terminating `;`.
            import_lines.update(range(lineno, end_lineno + 1))
            findings.append(
                Finding(
                    severity="ERROR",
                    check="submodule-cycle",
                    rel_path=rel_path,
                    line=lineno,
                    message=f"identifiers imported from primitives/data {REMEDY}",
                )
            )

        # Pass 2 — fully-qualified inline paths, which close the same cycle with
        # no import line to catch (issue #753).
        for lineno in _iter_qualified_lines(text, skip=import_lines):
            findings.append(
                Finding(
                    severity="ERROR",
                    check="submodule-cycle",
                    rel_path=rel_path,
                    line=lineno,
                    message=(
                        "identifiers referenced by fully-qualified path from "
                        f"primitives/data {REMEDY}"
                    ),
                )
            )

        yield from sorted(findings, key=lambda finding: finding.line)
