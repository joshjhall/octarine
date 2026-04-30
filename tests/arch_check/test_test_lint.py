"""Tests for Check 5: test-lint."""

from __future__ import annotations

from pathlib import Path

from scripts.arch_check.checks import test_lint


def test_no_allow_yields_no_findings(write_rs, tmp_repo: Path):
    write_rs("foo.rs", "fn main() {}\n")
    files = [tmp_repo / "crates/octarine/src/foo.rs"]
    assert list(test_lint.run(files=files, root=tmp_repo)) == []


def test_indexing_slicing_allow_yields_error(write_rs, tmp_repo: Path):
    write_rs("foo.rs", "#![allow(clippy::indexing_slicing)]\n")
    files = [tmp_repo / "crates/octarine/src/foo.rs"]
    findings = list(test_lint.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "ERROR"
    assert f.check == "test-lint"
    assert f.line == 1
    assert "indexing_slicing must not be allowed" in f.message


def test_inline_allow_attr_also_caught(write_rs, tmp_repo: Path):
    write_rs("foo.rs", "fn main() {}\n#[allow(clippy::indexing_slicing)]\nfn x() {}\n")
    files = [tmp_repo / "crates/octarine/src/foo.rs"]
    findings = list(test_lint.run(files=files, root=tmp_repo))
    assert [f.line for f in findings] == [2]


def test_allow_other_lints_not_caught(write_rs, tmp_repo: Path):
    write_rs("foo.rs", "#![allow(clippy::unwrap_used)]\n")
    files = [tmp_repo / "crates/octarine/src/foo.rs"]
    assert list(test_lint.run(files=files, root=tmp_repo)) == []
