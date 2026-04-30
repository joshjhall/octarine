"""Tests for Check 4: naming-return-type."""

from __future__ import annotations

from pathlib import Path

from scripts.arch_check.checks import naming_return_type


def test_is_returns_bool_no_finding(write_rs, tmp_repo: Path):
    write_rs("primitives/identifiers/foo.rs", "pub fn is_foo() -> bool { true }\n")
    findings = list(naming_return_type.run(staged_only=False, root=tmp_repo))
    assert findings == []


def test_validate_returns_result_no_finding(write_rs, tmp_repo: Path):
    write_rs(
        "primitives/identifiers/foo.rs",
        "pub fn validate_x(s: &str) -> Result<(), Problem> { Ok(()) }\n",
    )
    findings = list(naming_return_type.run(staged_only=False, root=tmp_repo))
    assert findings == []


def test_is_returns_option_yields_warn(write_rs, tmp_repo: Path):
    write_rs("primitives/identifiers/foo.rs", "pub fn is_foo(x: &str) -> Option<u32> { None }\n")
    findings = list(naming_return_type.run(staged_only=False, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].severity == "WARN"
    assert "is_* should return bool" in findings[0].message


def test_validate_returns_bool_yields_warn(write_rs, tmp_repo: Path):
    write_rs("primitives/identifiers/foo.rs", "pub fn validate_x(s: &str) -> bool { true }\n")
    findings = list(naming_return_type.run(staged_only=False, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].severity == "WARN"
    assert "validate_* should return Result" in findings[0].message


def test_two_pass_order_is_passes_first_then_validate(write_rs, tmp_repo: Path):
    # Bash runs all `is_*` regex matches per-file first, then all `validate_*`.
    # Same file with both — order matters for byte-identical output.
    content = (
        "pub fn validate_x(s: &str) -> bool { true }\n"
        "pub fn is_y(x: &str) -> Option<u32> { None }\n"
    )
    write_rs("primitives/identifiers/foo.rs", content)
    findings = list(naming_return_type.run(staged_only=False, root=tmp_repo))
    assert [f.message for f in findings] == [
        "is_* should return bool",
        "validate_* should return Result",
    ]


def test_is_returns_string_yields_warn(write_rs, tmp_repo: Path):
    write_rs("primitives/identifiers/foo.rs", "pub fn is_foo(x: &str) -> String { String::new() }\n")
    findings = list(naming_return_type.run(staged_only=False, root=tmp_repo))
    assert len(findings) == 1
    assert "is_* should return bool" in findings[0].message
