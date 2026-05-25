"""Tests for the doctest-ignores check.

Rules under test:
1. Bare ```ignore on a doc-comment fence yields an ERROR finding.
2. A justification comment within the preceding 3 doc lines suppresses it.
3. An `// arch-check: allow doctest-ignores` directive suppresses it.
4. Files under `primitives/` and `testing/` are skipped entirely.
5. ```rust,ignore and indented (inside `impl`) fences are also caught.
6. Plain ```rust and ```no_run fences are NOT flagged.
"""

from __future__ import annotations

from pathlib import Path

from scripts.arch_check.checks import doctest_ignores


def _files(tmp_repo: Path, rel: str) -> list[Path]:
    return [tmp_repo / "crates/octarine/src" / rel]


def test_bare_ignore_yields_error(write_rs, tmp_repo: Path):
    content = (
        "/// Example using the API.\n"
        "///\n"
        "/// ```ignore\n"
        "/// let x = foo();\n"
        "/// ```\n"
        "pub fn foo() {}\n"
    )
    write_rs("data/foo.rs", content)
    findings = list(doctest_ignores.run(files=_files(tmp_repo, "data/foo.rs"), root=tmp_repo))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "ERROR"
    assert f.check == "doctest-ignores"
    assert f.line == 3
    assert "unexplained" in f.message


def test_justification_in_preceding_line_suppresses(write_rs, tmp_repo: Path):
    content = (
        "/// Example using the API.\n"
        "/// Ignored because it requires a running tokio runtime.\n"
        "/// ```ignore\n"
        "/// foo().await;\n"
        "/// ```\n"
        "pub fn foo() {}\n"
    )
    write_rs("data/foo.rs", content)
    assert list(doctest_ignores.run(files=_files(tmp_repo, "data/foo.rs"), root=tmp_repo)) == []


def test_directive_suppresses(write_rs, tmp_repo: Path):
    content = (
        "/// Example.\n"
        "// arch-check: allow doctest-ignores -- unstable API under construction\n"
        "/// ```ignore\n"
        "/// foo();\n"
        "/// ```\n"
        "pub(crate) fn foo() {}\n"
    )
    write_rs("data/foo.rs", content)
    assert list(doctest_ignores.run(files=_files(tmp_repo, "data/foo.rs"), root=tmp_repo)) == []


def test_rust_ignore_variant_yields_warning(write_rs, tmp_repo: Path):
    # `rust,ignore` is a legal rustdoc form and must be caught too.
    content = (
        "/// Example.\n"
        "///\n"
        "/// ```rust,ignore\n"
        "/// let x = foo();\n"
        "/// ```\n"
        "pub fn foo() {}\n"
    )
    write_rs("data/foo.rs", content)
    findings = list(doctest_ignores.run(files=_files(tmp_repo, "data/foo.rs"), root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 3


def test_indented_fence_yields_warning(write_rs, tmp_repo: Path):
    # Inside an `impl` block, doc comments have leading whitespace.
    content = (
        "pub struct Thing;\n"
        "\n"
        "impl Thing {\n"
        "    /// Example.\n"
        "    ///\n"
        "    /// ```ignore\n"
        "    /// Thing.do_it();\n"
        "    /// ```\n"
        "    pub fn do_it(&self) {}\n"
        "}\n"
    )
    write_rs("data/foo.rs", content)
    findings = list(doctest_ignores.run(files=_files(tmp_repo, "data/foo.rs"), root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 6


def test_plain_rust_fence_not_flagged(write_rs, tmp_repo: Path):
    content = (
        "/// Example.\n"
        "///\n"
        "/// ```rust\n"
        "/// let x = 1;\n"
        "/// ```\n"
        "pub fn foo() {}\n"
    )
    write_rs("data/foo.rs", content)
    assert list(doctest_ignores.run(files=_files(tmp_repo, "data/foo.rs"), root=tmp_repo)) == []


def test_no_run_fence_not_flagged(write_rs, tmp_repo: Path):
    content = (
        "/// Example.\n"
        "///\n"
        "/// ```no_run\n"
        "/// foo();\n"
        "/// ```\n"
        "pub fn foo() {}\n"
    )
    write_rs("data/foo.rs", content)
    assert list(doctest_ignores.run(files=_files(tmp_repo, "data/foo.rs"), root=tmp_repo)) == []


def test_primitives_files_skipped(write_rs, tmp_repo: Path):
    content = (
        "/// ```ignore\n"
        "/// foo();\n"
        "/// ```\n"
        "pub(crate) fn foo() {}\n"
    )
    write_rs("primitives/foo.rs", content)
    assert list(doctest_ignores.run(files=_files(tmp_repo, "primitives/foo.rs"), root=tmp_repo)) == []


def test_testing_files_skipped(write_rs, tmp_repo: Path):
    content = "/// ```ignore\n/// foo();\n/// ```\npub fn foo() {}\n"
    write_rs("testing/foo.rs", content)
    assert list(doctest_ignores.run(files=_files(tmp_repo, "testing/foo.rs"), root=tmp_repo)) == []


def test_module_level_inner_doc_comment(write_rs, tmp_repo: Path):
    # `//!` module-level doc comments must also be caught.
    content = (
        "//! Module overview.\n"
        "//!\n"
        "//! ```ignore\n"
        "//! use crate::foo;\n"
        "//! ```\n"
    )
    write_rs("data/mod_doc.rs", content)
    findings = list(doctest_ignores.run(files=_files(tmp_repo, "data/mod_doc.rs"), root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 3


def test_two_unrelated_fences_each_evaluated(write_rs, tmp_repo: Path):
    # First fence has a justification (suppressed); second does not (flagged).
    # Separating the two doc blocks with an item resets the doc window so
    # the second fence cannot inherit the first's justification.
    content = (
        "/// Ignored because async I/O.\n"
        "/// ```ignore\n"
        "/// foo().await;\n"
        "/// ```\n"
        "pub fn foo() {}\n"
        "\n"
        "/// Plain doc.\n"
        "/// ```ignore\n"
        "/// bar();\n"
        "/// ```\n"
        "pub fn bar() {}\n"
    )
    write_rs("data/foo.rs", content)
    findings = list(doctest_ignores.run(files=_files(tmp_repo, "data/foo.rs"), root=tmp_repo))
    assert len(findings) == 1
    assert findings[0].line == 8
