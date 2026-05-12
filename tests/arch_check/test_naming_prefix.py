"""Tests for Check 3: naming-prefix."""

from __future__ import annotations

from pathlib import Path

from scripts.arch_check.checks import naming_prefix


def test_is_returns_bool_no_finding(write_rs, tmp_repo: Path):
    write_rs("primitives/identifiers/foo.rs", "pub fn is_foo() -> bool { true }\n")
    findings = list(naming_prefix.run(staged_only=False, root=tmp_repo))
    assert findings == []


def test_has_prefix_yields_error(write_rs, tmp_repo: Path):
    write_rs("primitives/identifiers/foo.rs", "pub fn has_foo() -> bool { true }\n")
    findings = list(naming_prefix.run(staged_only=False, root=tmp_repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "ERROR"
    assert f.check == "naming-prefix"
    assert "'has_foo'" in f.message


def test_remove_prefix_yields_error(write_rs, tmp_repo: Path):
    write_rs("primitives/identifiers/foo.rs", "pub fn remove_bar() {}\n")
    findings = list(naming_prefix.run(staged_only=False, root=tmp_repo))
    assert len(findings) == 1
    assert "'remove_bar'" in findings[0].message


def test_all_prohibited_prefixes(write_rs, tmp_repo: Path):
    content = "\n".join(
        f"pub fn {p}_x() {{}}"
        for p in ("has", "contains", "check", "verify", "ensure", "remove")
    ) + "\n"
    write_rs("primitives/identifiers/foo.rs", content)
    findings = list(naming_prefix.run(staged_only=False, root=tmp_repo))
    assert len(findings) == 6


def test_l3_identifiers_also_scanned(write_rs, tmp_repo: Path):
    write_rs("identifiers/foo.rs", "pub fn has_foo() -> bool { true }\n")
    findings = list(naming_prefix.run(staged_only=False, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].rel_path.startswith("crates/octarine/src/identifiers/")


def test_subdir_order_primitives_first(write_rs, tmp_repo: Path):
    write_rs("primitives/identifiers/p.rs", "pub fn has_x() {}\n")
    write_rs("identifiers/l.rs", "pub fn has_y() {}\n")
    findings = list(naming_prefix.run(staged_only=False, root=tmp_repo))
    # Bash iterates primitives/identifiers BEFORE identifiers.
    paths = [f.rel_path for f in findings]
    assert paths[0].startswith("crates/octarine/src/primitives/")
    assert paths[1].startswith("crates/octarine/src/identifiers/")


def test_extended_scope_covers_primitives_crypto_data_io_and_observe(
    write_rs, tmp_repo: Path
):
    write_rs("primitives/crypto/x.rs", "pub fn verify_x() {}\n")
    write_rs("primitives/data/y.rs", "pub fn ensure_y() {}\n")
    write_rs("primitives/io/z.rs", "pub fn check_z() {}\n")
    write_rs("observe/w.rs", "pub fn has_w() {}\n")
    findings = list(naming_prefix.run(staged_only=False, root=tmp_repo))
    assert {f.rel_path for f in findings} == {
        "crates/octarine/src/primitives/crypto/x.rs",
        "crates/octarine/src/primitives/data/y.rs",
        "crates/octarine/src/primitives/io/z.rs",
        "crates/octarine/src/observe/w.rs",
    }


def test_layer3_crypto_and_data_now_in_scope(write_rs, tmp_repo: Path):
    # As of #314, Layer 3 `crypto/` and `data/` are scanned too — the
    # deferred public-surface renames have landed.
    write_rs("crypto/auth/legacy.rs", "pub fn verify_legacy() {}\n")
    write_rs("data/paths/legacy.rs", "pub fn ensure_legacy() {}\n")
    findings = list(naming_prefix.run(staged_only=False, root=tmp_repo))
    assert {f.rel_path for f in findings} == {
        "crates/octarine/src/crypto/auth/legacy.rs",
        "crates/octarine/src/data/paths/legacy.rs",
    }
