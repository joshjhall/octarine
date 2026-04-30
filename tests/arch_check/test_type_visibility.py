"""Tests for Check 6: type-visibility.

Cross-file two-phase check. Output format omits the `:line` suffix.
"""

from __future__ import annotations

from pathlib import Path

from scripts.arch_check.checks import type_visibility


def test_no_overlap_yields_no_findings(write_rs, tmp_repo: Path):
    write_rs("primitives/foo/mod.rs", "pub(crate) use foo::{TypeA};\n")
    write_rs("data/foo.rs", "pub use crate::primitives::foo::TypeB;\n")
    findings = list(type_visibility.run(staged_only=False, root=tmp_repo))
    assert findings == []


def test_overlap_yields_error(write_rs, tmp_repo: Path):
    write_rs("primitives/foo/mod.rs", "pub(crate) use foo::{TypeA};\n")
    write_rs("data/foo.rs", "pub use crate::primitives::foo::TypeA;\n")
    findings = list(type_visibility.run(staged_only=False, root=tmp_repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "ERROR"
    assert f.check == "type-visibility"
    assert f.line is None
    assert "'TypeA' is pub(crate) in primitives" in f.message
    assert "L3 tries pub use at" in f.message


def test_multiline_pubcrate_collapsed(write_rs, tmp_repo: Path):
    write_rs(
        "primitives/foo/mod.rs",
        "pub(crate) use foo::{\n    TypeA,\n    TypeB,\n};\n",
    )
    write_rs("data/foo.rs", "pub use crate::primitives::foo::TypeB;\n")
    findings = list(type_visibility.run(staged_only=False, root=tmp_repo))
    assert len(findings) == 1
    assert "'TypeB'" in findings[0].message


def test_builder_suffix_excluded(write_rs, tmp_repo: Path):
    write_rs("primitives/foo/mod.rs", "pub(crate) use foo::{FooBuilder};\n")
    write_rs("data/foo.rs", "pub use crate::primitives::foo::FooBuilder;\n")
    findings = list(type_visibility.run(staged_only=False, root=tmp_repo))
    assert findings == []


def test_l3_files_under_primitives_skipped(write_rs, tmp_repo: Path):
    write_rs("primitives/foo/mod.rs", "pub(crate) use foo::{TypeA};\n")
    # File inside /primitives/ should NOT count as L3, even if it has `pub use`.
    write_rs("primitives/bar/sub.rs", "pub use crate::primitives::foo::TypeA;\n")
    findings = list(type_visibility.run(staged_only=False, root=tmp_repo))
    assert findings == []


def test_findings_sorted_alphabetically(write_rs, tmp_repo: Path):
    # Multiple overlaps: Python sorts alphabetically (determinism over bash hash).
    write_rs("primitives/foo/mod.rs", "pub(crate) use foo::{Zebra, Alpha, Mango};\n")
    write_rs(
        "data/foo.rs",
        "pub use crate::primitives::foo::Zebra;\n"
        "pub use crate::primitives::foo::Alpha;\n"
        "pub use crate::primitives::foo::Mango;\n",
    )
    findings = list(type_visibility.run(staged_only=False, root=tmp_repo))
    assert [f.message.split("'")[1] for f in findings] == ["Alpha", "Mango", "Zebra"]
