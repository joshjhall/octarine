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


def test_bare_module_import_is_caught(write_rs, tmp_repo: Path):
    """`use …::identifiers;` imports the module whole — same cycle, no `::` tail."""
    write_rs("primitives/data/x.rs", "use crate::primitives::identifiers;\n")
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 1


def test_aliased_module_import_is_caught(write_rs, tmp_repo: Path):
    write_rs("primitives/data/x.rs", "use crate::primitives::identifiers as ids;\n")
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1


def test_bare_module_import_inside_brace_group_is_caught(write_rs, tmp_repo: Path):
    write_rs("primitives/data/x.rs", "use crate::primitives::{identifiers, types};\n")
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1


def test_block_comment_semicolon_does_not_truncate_the_join(write_rs, tmp_repo: Path):
    """`/* … */` must not end the statement early, exactly as `//` must not."""
    write_rs(
        "primitives/data/paths/mod.rs",
        "use crate::primitives::{\n"
        "    types::Problem, /* fixes bug; see issue */\n"
        "    identifiers::network::Foo,\n"
        "};\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/paths/mod.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 1


def test_forbidden_import_with_trailing_comment_is_still_caught(write_rs, tmp_repo: Path):
    """Stripping the comment must not take the real import with it."""
    write_rs(
        "primitives/data/x.rs",
        "use crate::primitives::identifiers::network::Foo; // needed for X\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 1


def test_block_comment_spanning_lines_does_not_truncate_the_join(write_rs, tmp_repo: Path):
    """A block comment may legitimately close on a later line — valid Rust.

    Stripping per physical line cannot see such a span, so the `;` inside it
    ended the join early and the forbidden segment below was dropped.
    """
    write_rs(
        "primitives/data/paths/mod.rs",
        "use crate::primitives::{\n"
        "    types::Problem, /* fixes bug;\n"
        "    see issue */\n"
        "    identifiers::network::Foo,\n"
        "};\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/paths/mod.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 1


def test_alias_to_the_name_identifiers_is_not_flagged(write_rs, tmp_repo: Path):
    """Aliasing an unrelated import TO this name introduces no dependency.

    `helper as identifiers` renames something in data; it does not import the
    identifiers module, so flagging it would block legitimate code.
    """
    write_rs(
        "primitives/data/x.rs",
        "use crate::primitives::data::helper as identifiers;\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []


def test_line_numbers_survive_block_comment_stripping(write_rs, tmp_repo: Path):
    """Stripping must preserve newlines, or later findings report a wrong line."""
    write_rs(
        "primitives/data/x.rs",
        "/* a\n   multi-line\n   banner */\nuse crate::primitives::identifiers::crypto::KeyType;\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 4


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


def test_fully_qualified_inline_call_is_caught(write_rs, tmp_repo: Path):
    """The exact form that existed at primitives/data/network/url.rs (issue #753).

    A fully-qualified inline call closes the same cycle with no import line to
    catch. This case was the documented gap until #753 closed it.
    """
    write_rs(
        "primitives/data/network/url.rs",
        "fn f(s: &str) -> bool {\n"
        "    crate::primitives::identifiers::network::Builder::new().is_uuid(s)\n"
        "}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/network/url.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "ERROR"
    assert f.check == "submodule-cycle"
    assert f.line == 2
    assert "fully-qualified path" in f.message


def test_relative_super_inline_call_is_caught(write_rs, tmp_repo: Path):
    """The relative spelling reaches the same module and closes the same cycle."""
    write_rs(
        "primitives/data/network/url.rs",
        "fn f(s: &str) -> bool {\n    super::super::identifiers::network::is_uuid(s)\n}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/network/url.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 2


def test_qualified_path_as_nested_argument_is_caught(write_rs, tmp_repo: Path):
    """The path need not head the expression - a nested call is still a call."""
    write_rs(
        "primitives/data/network/url.rs",
        "fn f(s: &str) -> bool {\n"
        "    matches!(crate::primitives::identifiers::network::classify(s), Some(_))\n"
        "}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/network/url.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 2


def test_qualified_type_annotation_is_caught(write_rs, tmp_repo: Path):
    """Naming the type is as much a dependency as calling into it."""
    write_rs(
        "primitives/data/network/url.rs",
        "fn f() -> crate::primitives::identifiers::network::Kind {\n    todo!()\n}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/network/url.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 1


def test_forbidden_import_is_reported_once(write_rs, tmp_repo: Path):
    """A `use` line is also a qualified path - it must not be double-reported."""
    write_rs(
        "primitives/data/x.rs",
        "use crate::primitives::identifiers::network::Foo;\n\nfn f() -> Foo {\n    todo!()\n}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 1
    assert "imported" in findings[0].message


def test_multiline_forbidden_import_is_reported_once(write_rs, tmp_repo: Path):
    """The inline pass must skip every line a reported import spans, not just its first.

    A top-level brace group puts the rooted path on a *continuation* line, which
    the inline pass would otherwise report a second time.
    """
    write_rs(
        "primitives/data/x.rs",
        "use {\n"
        "    crate::primitives::identifiers::network::Foo,\n"
        "    crate::primitives::types::Problem,\n"
        "};\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 1
    assert "imported" in findings[0].message


def test_qualified_path_in_doc_comment_is_not_flagged(write_rs, tmp_repo: Path):
    """The real data/mod.rs and data/network/mod.rs shape - docs, not dependencies."""
    write_rs(
        "primitives/data/mod.rs",
        "//! - `primitives::identifiers` - CLASSIFICATION: what is it?\n"
        "//   crate::primitives::identifiers::{IdentifierBuilder, ...}\n"
        "/// See [`crate::primitives::identifiers::network`] for classification.\n"
        "pub fn f() {}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/mod.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []


def test_qualified_path_in_block_comment_is_not_flagged(write_rs, tmp_repo: Path):
    """A block comment spanning lines is stripped whole before the inline pass."""
    write_rs(
        "primitives/data/x.rs",
        "/*\n * crate::primitives::identifiers::network::is_uuid(s)\n */\npub fn f() {}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []


def test_qualified_path_in_string_literal_is_not_flagged(write_rs, tmp_repo: Path):
    """A quoted path is data - an error message or fixture, not a dependency."""
    write_rs(
        "primitives/data/x.rs",
        'pub fn f() -> &\'static str {\n'
        '    "crate::primitives::identifiers::network::is_uuid"\n'
        "}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []


def test_string_containing_slashes_does_not_hide_a_later_call(write_rs, tmp_repo: Path):
    """A `//` inside a string is not a comment, so it must not swallow real code.

    Blanking comments before literals truncated the line at the `//` of a URL and
    dropped the forbidden call after it - a false negative in this very check.
    """
    write_rs(
        "primitives/data/x.rs",
        "fn f(s: &str) -> bool {\n"
        '    log_url("http://example.com", crate::primitives::identifiers::network::is_uuid(s))\n'
        "}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 2


def test_string_containing_block_comment_open_does_not_hide_a_later_call(
    write_rs, tmp_repo: Path
):
    """A `/*` inside a string must not open a comment that runs to the next `*/`."""
    write_rs(
        "primitives/data/x.rs",
        'const GLOB: &str = "src/*";\n'
        "fn f(s: &str) -> bool {\n"
        "    crate::primitives::identifiers::network::is_uuid(s)\n"
        "}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 3


def test_quote_inside_comment_does_not_hide_a_later_call(write_rs, tmp_repo: Path):
    """The mirror case: an apostrophe in a comment must not open a char literal."""
    write_rs(
        "primitives/data/x.rs",
        "// it's the classification module\n"
        "fn f(s: &str) -> bool {\n"
        "    crate::primitives::identifiers::network::is_uuid(s)\n"
        "}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 3


def test_multiline_string_keeps_later_line_numbers_accurate(write_rs, tmp_repo: Path):
    """Blanking a multi-line literal must preserve its newlines, or lines shift."""
    write_rs(
        "primitives/data/x.rs",
        'const DOC: &str = "line one\nline two\nline three";\n'
        "fn f(s: &str) -> bool {\n"
        "    crate::primitives::identifiers::network::is_uuid(s)\n"
        "}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 5


def test_raw_hash_string_is_blanked(write_rs, tmp_repo: Path):
    """`r#"…"#` holds a quote without ending, and must not be read as code."""
    write_rs(
        "primitives/data/x.rs",
        'const SAMPLE: &str = r#"uses "crate::primitives::identifiers::network""#;\n'
        "pub fn f() {}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []


def test_lifetime_does_not_swallow_a_later_call(write_rs, tmp_repo: Path):
    """A lifetime `'a` is an unterminated quote - it must not blank the rest."""
    write_rs(
        "primitives/data/x.rs",
        "fn f<'a>(s: &'a str) -> bool {\n"
        "    crate::primitives::identifiers::network::is_uuid(s)\n"
        "}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 2


def test_semicolon_in_trailing_comment_does_not_truncate_import(
    write_rs, tmp_repo: Path
):
    """The pre-existing reason comments are blanked before the import join."""
    write_rs(
        "primitives/data/x.rs",
        "use crate::primitives::{ // keep sorted; see mod.rs\n"
        "    identifiers::network::Foo,\n"
        "};\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 1


def test_nested_block_comment_is_consumed_whole(write_rs, tmp_repo: Path):
    """Rust nests block comments, so the scan tracks depth rather than first `*/`.

    Stopping at the inner `*/` would leave the outer comment's tail as live code.
    """
    write_rs(
        "primitives/data/x.rs",
        "/* outer /* inner */ crate::primitives::identifiers::network::is_uuid(s) */\n"
        "pub fn f() {}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []


def test_code_after_nested_block_comment_is_still_scanned(write_rs, tmp_repo: Path):
    """The mirror: over-counting depth would swallow the real call that follows."""
    write_rs(
        "primitives/data/x.rs",
        "/* outer /* inner */ still outer */\n"
        "fn f(s: &str) -> bool {\n"
        "    crate::primitives::identifiers::network::is_uuid(s)\n"
        "}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 3


def test_escaped_quote_in_string_does_not_end_it_early(write_rs, tmp_repo: Path):
    """An escaped quote must not terminate the literal and expose its contents."""
    write_rs(
        "primitives/data/x.rs",
        'const S: &str = "a \\" crate::primitives::identifiers::network::is_uuid";\n'
        "pub fn f() {}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []


def test_escaped_backslash_ends_string_so_later_code_is_scanned(
    write_rs, tmp_repo: Path
):
    """`"\\\\"` ends at the second quote - the call after it is live code."""
    write_rs(
        "primitives/data/x.rs",
        'fn f(s: &str) -> bool {\n'
        '    g("\\\\", crate::primitives::identifiers::network::is_uuid(s))\n'
        "}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 2


def test_escaped_quote_char_literal_does_not_swallow_later_code(
    write_rs, tmp_repo: Path
):
    """`'\\''` is a char literal holding a quote; it must close at its own end."""
    write_rs(
        "primitives/data/x.rs",
        "fn f(s: &str) -> bool {\n"
        "    g('\\'', crate::primitives::identifiers::network::is_uuid(s))\n"
        "}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 2


def test_single_super_hop_inline_call_is_caught(write_rs, tmp_repo: Path):
    """One `super::` hop - the zero-repetition branch of the rooted pattern."""
    write_rs(
        "primitives/data/network/url.rs",
        "fn f(s: &str) -> bool {\n    super::identifiers::network::is_uuid(s)\n}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/network/url.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 2


def test_bare_raw_string_is_blanked(write_rs, tmp_repo: Path):
    """`r"…"` with no hash delimiter is a raw string too."""
    write_rs(
        "primitives/data/x.rs",
        'const SAMPLE: &str = r"crate::primitives::identifiers::network::is_uuid";\n'
        "pub fn f() {}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []


def test_wrapped_qualified_path_is_caught(write_rs, tmp_repo: Path):
    """rustfmt breaks an overlong path at `::`; the violation must not hide there."""
    write_rs(
        "primitives/data/network/url.rs",
        "fn f(s: &str) -> bool {\n"
        "    crate::primitives::\n"
        "        identifiers::network::is_uuid(s)\n"
        "}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/network/url.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    # Reported against the line the path starts on.
    assert findings[0].line == 2


def test_path_wrapped_across_three_lines_is_caught(write_rs, tmp_repo: Path):
    """The root alone on its own line: a one-line-lookahead join would miss this."""
    write_rs(
        "primitives/data/network/url.rs",
        "fn f(s: &str) -> bool {\n"
        "    crate::\n"
        "        primitives::\n"
        "            identifiers::network::is_uuid(s)\n"
        "}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/network/url.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 2


def test_wrapped_super_path_is_caught(write_rs, tmp_repo: Path):
    """The relative root wraps too, including between its own `super::` hops."""
    write_rs(
        "primitives/data/network/url.rs",
        "fn f(s: &str) -> bool {\n"
        "    super::\n"
        "        super::\n"
        "            identifiers::network::is_uuid(s)\n"
        "}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/network/url.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 2


def test_multi_hash_raw_string_is_blanked(write_rs, tmp_repo: Path):
    """`r##"…"##` ends only at `"##` - a `"#` inside it must not close it early."""
    write_rs(
        "primitives/data/x.rs",
        'const SAMPLE: &str = r##"holds "# then '
        'crate::primitives::identifiers::network::is_uuid"##;\n'
        "pub fn f() {}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []


def test_identifier_ending_in_crate_is_not_flagged(write_rs, tmp_repo: Path):
    """The left boundary on the root: `my_crate::identifiers::` is another tree."""
    write_rs(
        "primitives/data/x.rs",
        "pub fn f(s: &str) -> bool {\n    my_crate::identifiers::network::is_uuid(s)\n}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []


def test_unrelated_crate_qualified_path_is_not_flagged(write_rs, tmp_repo: Path):
    """`other_crate::identifiers::` is a different module tree entirely."""
    write_rs(
        "primitives/data/x.rs",
        "pub fn f(s: &str) -> bool {\n    external_identifiers::is_uuid(s)\n}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/x.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []


def test_sibling_module_qualified_path_is_not_flagged(write_rs, tmp_repo: Path):
    """The permitted direction: data reaching its own shared types."""
    write_rs(
        "primitives/data/network/url.rs",
        "fn f(s: &str) -> bool {\n    crate::primitives::types::is_uuid_shape(s)\n}\n",
    )
    files = [tmp_repo / "crates/octarine/src/primitives/data/network/url.rs"]
    findings = list(submodule_cycle.run(files=files, root=tmp_repo))
    assert findings == []
