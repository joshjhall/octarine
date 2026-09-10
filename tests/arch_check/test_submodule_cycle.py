"""Tests for the submodule-cycle check.

The check guards the one-way `identifiers → data` flow inside Layer 1 by
rejecting imports that run the other way. These cases pin down every import
spelling that closes the cycle, plus the one documented form that does not.
"""

from __future__ import annotations

from pathlib import Path

from scripts.arch_check.checks import submodule_cycle


def test_clean_file_yields_no_findings(write_rs, tmp_repo: Path):
    write_rs("primitives/data/crypto/types.rs", "use crate::primitives::types::KeyType;\n")
    files = [tmp_repo / "crates/octarine/src/primitives/data/crypto/types.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []


def test_absolute_use_yields_error(write_rs, tmp_repo: Path):
    write_rs(
        "primitives/data/crypto/types.rs",
        "use chrono::Utc;\nuse crate::primitives::identifiers::crypto::KeyType;\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/crypto/types.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "ERROR"
    assert f.check == "submodule-cycle"
    assert f.line == 2
    assert "closes a Layer 1 cycle" in f.message


def test_pub_use_reexport_is_caught(write_rs, tmp_repo: Path):
    write_rs("primitives/data/mod.rs", "pub use crate::primitives::identifiers::crypto::KeyType;\n")
    files = [tmp_repo / "crates/octarine/src/primitives/data/mod.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 1


def test_pub_crate_use_reexport_is_caught(write_rs, tmp_repo: Path):
    """`pub(crate) use` is the idiom actually used across primitives/data."""
    write_rs(
        "primitives/data/paths/mod.rs",
        "pub(crate) use crate::primitives::identifiers::network::Foo;\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/paths/mod.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 1


def test_pub_super_use_reexport_is_caught(write_rs, tmp_repo: Path):
    write_rs(
        "primitives/data/paths/mod.rs",
        "pub(super) use crate::primitives::identifiers::network::Foo;\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/paths/mod.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1


def test_relative_super_import_is_caught(write_rs, tmp_repo: Path):
    """A relative path closes the same cycle without naming `crate::primitives`."""
    write_rs(
        "primitives/data/crypto/ssh.rs",
        "use super::super::identifiers::crypto::KeyType;\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/crypto/ssh.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 1


def test_single_line_brace_group_is_caught(write_rs, tmp_repo: Path):
    """`use crate::primitives::{…}` is an established idiom in this crate."""
    write_rs(
        "primitives/data/crypto/types.rs",
        "use crate::primitives::{identifiers::crypto::KeyType, types::Problem};\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/crypto/types.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 1


def test_relative_brace_group_is_caught(write_rs, tmp_repo: Path):
    write_rs(
        "primitives/data/crypto/ssh.rs",
        "use super::{identifiers::network::Foo, types::Bar};\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/crypto/ssh.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1


def test_multi_line_brace_group_is_caught(write_rs, tmp_repo: Path):
    """The rustfmt-produced multi-line form must be joined before matching.

    The `use` keyword and the forbidden segment land on different lines, so a
    per-line matcher sees neither a complete import nor a complete path.
    """
    write_rs(
        "primitives/data/paths/mod.rs",
        "pub(crate) use crate::primitives::{\n"
        "    identifiers::network::Foo,\n"
        "    types::Problem,\n"
        "};\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/paths/mod.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    # Reported against the `use` keyword, not the continuation line.
    assert findings[0].line == 1


def test_multi_line_brace_group_without_identifiers_is_clean(write_rs, tmp_repo: Path):
    """Joining lines must not create false positives for innocent groups."""
    write_rs(
        "primitives/data/paths/mod.rs",
        "pub(crate) use types::{\n    BoundaryStrategy,\n    FileCategory,\n};\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/paths/mod.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []


def test_comment_semicolon_does_not_truncate_the_join(write_rs, tmp_repo: Path):
    """A `;` inside a trailing `//` comment must not end the statement early.

    If it does, the join stops before reaching the forbidden segment and the
    import is silently missed.
    """
    write_rs(
        "primitives/data/paths/mod.rs",
        "use crate::primitives::{\n"
        "    types::Problem, // fixes bug; see issue\n"
        "    identifiers::network::Foo,\n"
        "};\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/paths/mod.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 1


def test_comment_semicolon_on_opening_line_does_not_truncate(write_rs, tmp_repo: Path):
    """The same bug, hit on the `use` line itself before any join is attempted."""
    write_rs(
        "primitives/data/paths/mod.rs",
        "use crate::primitives::{ // order matters; keep this\n"
        "    identifiers::network::Foo,\n"
        "};\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/paths/mod.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 1


def test_commented_out_forbidden_import_is_not_flagged(write_rs, tmp_repo: Path):
    """Stripping comments must also stop a commented-out import false-positiving."""
    write_rs(
        "primitives/data/x.rs",
        "use crate::primitives::types::Problem; // use crate::primitives::identifiers::Foo;\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []


def test_unterminated_statement_terminates_at_eof(write_rs, tmp_repo: Path):
    """The join is EOF-bounded, so a missing `;` cannot hang the scanner."""
    write_rs(
        "primitives/data/truncated.rs",
        "use crate::primitives::{\n    identifiers::network::Foo,\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/truncated.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 1


def test_multiple_imports_yield_one_finding_each(write_rs, tmp_repo: Path):
    content = (
        "use crate::primitives::identifiers::crypto::KeyType;\n"
        "use crate::primitives::types::Problem;\n"
        "pub(crate) use crate::primitives::identifiers::network::Foo;\n"
    )
    write_rs("primitives/data/multi.rs", content)
    files = [tmp_repo / "crates/octarine/src/primitives/data/multi.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert [f.line for f in findings] == [1, 3]


def test_sibling_data_import_is_not_flagged(write_rs, tmp_repo: Path):
    """`use super::types::…` within data is the normal case, not a cycle."""
    write_rs("primitives/data/crypto/ssh.rs", "use super::types::ParsedSshPublicKey;\n")
    files = [tmp_repo / "crates/octarine/src/primitives/data/crypto/ssh.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []


def test_word_ending_in_identifiers_is_not_flagged(write_rs, tmp_repo: Path):
    """A module whose name merely ends in `identifiers` must not false-positive."""
    write_rs("primitives/data/x.rs", "use crate::primitives::data::my_identifiers::Foo;\n")
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []


def test_non_import_mention_is_not_flagged(write_rs, tmp_repo: Path):
    """A doc comment referencing the module is documentation, not a dependency."""
    write_rs(
        "primitives/data/mod.rs",
        "//! - `primitives::identifiers` - CLASSIFICATION: what is it?\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/mod.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []


def test_fully_qualified_inline_call_is_not_caught(write_rs, tmp_repo: Path):
    """Documented limitation, pinned so a future change to it is deliberate.

    A fully-qualified inline call closes the same cycle but has no import line.
    One such call exists at primitives/data/network/url.rs; widening the check to
    cover it is tracked in issue #753. This test asserts the CURRENT behaviour so
    that closing the gap fails here loudly rather than silently.
    """
    write_rs(
        "primitives/data/network/url.rs",
        "fn f(s: &str) -> bool {\n"
        "    crate::primitives::identifiers::network::Builder::new().is_uuid(s)\n"
        "}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/network/url.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []
