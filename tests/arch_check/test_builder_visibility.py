"""Tests for Check 7: builder-visibility.

File scope is a SINGLE-LEVEL glob: primitives/mod.rs and primitives/*/mod.rs.
Deeper subdirectories (e.g. primitives/auth/csrf/mod.rs) are NOT scanned.
"""

from __future__ import annotations

from pathlib import Path

from scripts.arch_check.checks import builder_visibility


def test_pubcrate_use_is_ok(write_rs, tmp_repo: Path):
    write_rs("primitives/foo/mod.rs", "pub(crate) use bar::{FooBuilder, do_thing};\n")
    findings = list(builder_visibility.run(root=tmp_repo))
    assert findings == []


def test_pure_type_re_export_is_ok(write_rs, tmp_repo: Path):
    write_rs("primitives/foo/mod.rs", "pub use bar::{FooConfig};\n")
    findings = list(builder_visibility.run(root=tmp_repo))
    assert findings == []


def test_pub_use_builder_yields_warn(write_rs, tmp_repo: Path):
    write_rs("primitives/foo/mod.rs", "pub use bar::{FooBuilder};\n")
    findings = list(builder_visibility.run(root=tmp_repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "WARN"
    assert "'FooBuilder'" in f.message
    assert "must go through L3 wrappers" in f.message


def test_pub_use_snake_fn_yields_warn(write_rs, tmp_repo: Path):
    write_rs("primitives/foo/mod.rs", "pub use bar::{do_thing};\n")
    findings = list(builder_visibility.run(root=tmp_repo))
    assert len(findings) == 1
    assert "'do_thing' (function)" in findings[0].message


def test_keywords_inside_braces_excluded(write_rs, tmp_repo: Path):
    write_rs("primitives/foo/mod.rs", "pub use bar::{self, do_thing};\n")
    findings = list(builder_visibility.run(root=tmp_repo))
    assert len(findings) == 1
    assert "'do_thing'" in findings[0].message
    assert all("'self'" not in f.message for f in findings)


def test_comment_lines_skipped(write_rs, tmp_repo: Path):
    write_rs("primitives/foo/mod.rs", "// pub use bar::{FooBuilder};\n")
    findings = list(builder_visibility.run(root=tmp_repo))
    assert findings == []


def test_top_level_primitives_mod_in_scope(write_rs, tmp_repo: Path):
    write_rs("primitives/mod.rs", "pub use bar::{FooBuilder};\n")
    findings = list(builder_visibility.run(root=tmp_repo))
    assert len(findings) == 1


def test_deeper_nested_mod_rs_NOT_in_scope(write_rs, tmp_repo: Path):
    # Single-level glob — primitives/auth/csrf/mod.rs is NOT scanned.
    write_rs("primitives/auth/csrf/mod.rs", "pub use bar::{FooBuilder};\n")
    findings = list(builder_visibility.run(root=tmp_repo))
    assert findings == []


def test_mixed_builder_and_fn_on_one_line(write_rs, tmp_repo: Path):
    write_rs("primitives/foo/mod.rs", "pub use bar::{FooBuilder, do_thing};\n")
    findings = list(builder_visibility.run(root=tmp_repo))
    # Bash emits Builder warnings before fn warnings within the same line.
    assert len(findings) == 2
    assert "'FooBuilder'" in findings[0].message
    assert "'do_thing'" in findings[1].message
