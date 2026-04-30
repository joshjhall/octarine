"""Unit tests for `format_finding` and Finding dataclass.

These pin down the exact output format that bash produces (parity-critical):
- `[ERROR] <check>: <rel>:<line> -- <msg>`
- `[WARN]  <check>: <rel>:<line> -- <msg>`  (two spaces after `]`)
- `[ERROR] type-visibility: <rel> -- <msg>` (no `:line` suffix, line=None)
"""

from __future__ import annotations

from scripts.arch_check.core import Finding, format_finding


def test_error_with_line():
    f = Finding(
        severity="ERROR",
        check="layer-boundary",
        rel_path="crates/octarine/src/primitives/foo.rs",
        line=42,
        message="observe imported in Layer 1 (primitives)",
    )
    assert format_finding(f) == (
        "[ERROR] layer-boundary: "
        "crates/octarine/src/primitives/foo.rs:42 -- "
        "observe imported in Layer 1 (primitives)"
    )


def test_warn_has_two_spaces_after_bracket():
    f = Finding(
        severity="WARN",
        check="naming-return-type",
        rel_path="x.rs",
        line=1,
        message="is_* should return bool",
    )
    out = format_finding(f)
    # Critical: `[WARN]` followed by exactly TWO spaces (column-align with `[ERROR]`).
    assert out.startswith("[WARN]  naming-return-type:"), repr(out)
    assert "[WARN]   " not in out  # not three spaces
    assert "[WARN] n" not in out  # not one space


def test_error_check6_no_line_suffix():
    f = Finding(
        severity="ERROR",
        check="type-visibility",
        rel_path="crates/octarine/src/primitives/foo/mod.rs",
        line=None,
        message="'Bar' is pub(crate) in primitives but L3 tries pub use at l3/foo.rs",
    )
    out = format_finding(f)
    assert out == (
        "[ERROR] type-visibility: "
        "crates/octarine/src/primitives/foo/mod.rs -- "
        "'Bar' is pub(crate) in primitives but L3 tries pub use at l3/foo.rs"
    )
    assert ":" not in out.split("--")[0].split(": ", 1)[1]


def test_finding_is_frozen():
    import dataclasses

    f = Finding(severity="ERROR", check="x", rel_path="y", message="z")
    assert dataclasses.is_dataclass(f)
