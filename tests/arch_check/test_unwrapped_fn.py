"""Tests for Check 2: unwrapped-fn.

The check now collapses multi-line `pub use crate::primitives::X::{ ... }`
blocks before iteration, so multi-line forms produce findings just like
single-line forms. Intentional bare re-exports can opt out with an inline
`// arch-check: allow unwrapped-fn` directive.
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


def test_multiline_block_with_lowercase_yields_warning(write_rs, tmp_repo: Path):
    # After collapsing, the body of the multi-line block is visible on the
    # head line (line 1), so the lowercase function name fires the check.
    content = "pub use crate::primitives::foo::{\n    do_thing,\n    AnotherType,\n};\n"
    write_rs("data/foo.rs", content)
    files = [tmp_repo / "crates/octarine/src/data/foo.rs"]
    findings = list(unwrapped_fn.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "WARN"
    assert f.check == "unwrapped-fn"
    assert f.line == 1


def test_multiline_block_pascal_only_yields_no_findings(write_rs, tmp_repo: Path):
    # Multi-line block with only PascalCase types must NOT fire — proves the
    # collapse doesn't introduce false positives for legitimate type-only
    # re-exports.
    content = "pub use crate::primitives::foo::{\n    TypeA,\n    TypeB,\n};\n"
    write_rs("data/foo.rs", content)
    files = [tmp_repo / "crates/octarine/src/data/foo.rs"]
    assert list(unwrapped_fn.run(files=files, root=tmp_repo)) == []


def test_directive_on_preceding_line_suppresses_finding(write_rs, tmp_repo: Path):
    content = (
        "// arch-check: allow unwrapped-fn -- intentional raw RNG\n"
        "pub use crate::primitives::foo::{do_thing, MyType};\n"
    )
    write_rs("data/foo.rs", content)
    files = [tmp_repo / "crates/octarine/src/data/foo.rs"]
    assert list(unwrapped_fn.run(files=files, root=tmp_repo)) == []


def test_directive_on_same_line_trailing_comment_suppresses_finding(
    write_rs, tmp_repo: Path
):
    content = (
        "pub use crate::primitives::foo::{do_thing, MyType}; "
        "// arch-check: allow unwrapped-fn -- intentional\n"
    )
    write_rs("data/foo.rs", content)
    files = [tmp_repo / "crates/octarine/src/data/foo.rs"]
    assert list(unwrapped_fn.run(files=files, root=tmp_repo)) == []


def test_directive_for_different_check_does_not_suppress(write_rs, tmp_repo: Path):
    # A directive for a different check must NOT suppress this one.
    content = (
        "// arch-check: allow naming-prefix\n"
        "pub use crate::primitives::foo::{do_thing, MyType};\n"
    )
    write_rs("data/foo.rs", content)
    files = [tmp_repo / "crates/octarine/src/data/foo.rs"]
    findings = list(unwrapped_fn.run(files=files, root=tmp_repo))
    assert len(findings) == 1


def test_files_under_primitives_are_skipped(write_rs, tmp_repo: Path):
    write_rs("primitives/foo.rs", "pub use crate::primitives::bar::{do_thing};\n")
    files = [tmp_repo / "crates/octarine/src/primitives/foo.rs"]
    assert list(unwrapped_fn.run(files=files, root=tmp_repo)) == []
