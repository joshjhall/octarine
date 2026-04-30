"""Tests for Check 2: unwrapped-fn.

This test suite documents the **bash parity bug**: multi-line `pub use
crate::primitives::X::{ ... }` blocks are silently skipped because bash
greps line-by-line. The Python rewrite preserves this behavior verbatim
to keep byte-identical output. A separate follow-up issue tracks the fix.
"""

from __future__ import annotations

from pathlib import Path

from scripts.arch_check.checks import unwrapped_fn


def test_pascal_case_only_yields_no_findings(write_rs, tmp_repo: Path):
    # Only PascalCase types — should not match `[{,]\s*[a-z]...`.
    write_rs("data/foo.rs", "pub use crate::primitives::foo::{TypeA, TypeB};\n")
    files = [tmp_repo / "crates/octarine/src/data/foo.rs"]
    assert list(unwrapped_fn.run(files=files, root=tmp_repo)) == []


def test_single_line_braced_lowercase_yields_warning(write_rs, tmp_repo: Path):
    write_rs("data/foo.rs", "pub use crate::primitives::foo::{do_thing, MyType};\n")
    files = [tmp_repo / "crates/octarine/src/data/foo.rs"]
    findings = list(unwrapped_fn.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "WARN"
    assert f.check == "unwrapped-fn"
    assert f.line == 1


def test_multiline_block_does_not_fire_parity_bug(write_rs, tmp_repo: Path):
    # Bash bug: the `[{,]\s*[a-z]` regex never sees the body lines.
    # Preserved verbatim — assert NO finding.
    content = "pub use crate::primitives::foo::{\n    do_thing,\n    AnotherType,\n};\n"
    write_rs("data/foo.rs", content)
    files = [tmp_repo / "crates/octarine/src/data/foo.rs"]
    assert list(unwrapped_fn.run(files=files, root=tmp_repo)) == []


def test_files_under_primitives_are_skipped(write_rs, tmp_repo: Path):
    write_rs("primitives/foo.rs", "pub use crate::primitives::bar::{do_thing};\n")
    files = [tmp_repo / "crates/octarine/src/primitives/foo.rs"]
    assert list(unwrapped_fn.run(files=files, root=tmp_repo)) == []
