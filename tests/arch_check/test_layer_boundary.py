"""Tests for Check 1: layer-boundary."""

from __future__ import annotations

from pathlib import Path

from scripts.arch_check.checks import layer_boundary


def test_no_observe_import_yields_no_findings(write_rs, tmp_repo: Path):
    write_rs("primitives/foo.rs", "use crate::primitives::types::Problem;\n")
    files = [tmp_repo / "crates/octarine/src/primitives/foo.rs"]
    findings = list(layer_boundary.run(files=files, root=tmp_repo))
    assert findings == []


def test_observe_import_yields_error(write_rs, tmp_repo: Path):
    write_rs("primitives/bad.rs", "use crate::primitives::types::Problem;\nuse crate::observe::Foo;\n")
    files = [tmp_repo / "crates/octarine/src/primitives/bad.rs"]
    findings = list(layer_boundary.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "ERROR"
    assert f.check == "layer-boundary"
    assert f.line == 2
    assert "observe imported in Layer 1" in f.message


def test_substring_match_catches_glob_imports(write_rs, tmp_repo: Path):
    write_rs("primitives/glob.rs", "use crate::observe::*;\n")
    files = [tmp_repo / "crates/octarine/src/primitives/glob.rs"]
    findings = list(layer_boundary.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 1


def test_multiple_observe_imports_yield_multiple_findings(write_rs, tmp_repo: Path):
    content = "use crate::observe::Foo;\nuse crate::primitives::Bar;\nuse crate::observe::Baz;\n"
    write_rs("primitives/multi.rs", content)
    files = [tmp_repo / "crates/octarine/src/primitives/multi.rs"]
    findings = list(layer_boundary.run(files=files, root=tmp_repo))
    assert [f.line for f in findings] == [1, 3]
