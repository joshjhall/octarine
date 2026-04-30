"""Unit tests for the Rust `use` statement collapser."""

from __future__ import annotations

from scripts.arch_check.rust_parse import collapse_use_statements


def test_collapse_pubcrate_multiline():
    text = "pub(crate) use foo::{\n    A,\n    B,\n};\n"
    out = collapse_use_statements(text, kind="pubcrate")
    # The `use` body becomes a single line; the trailing `;` and `\n` stay.
    assert "\n" not in out.split(";")[0]
    assert "pub(crate) use foo::{" in out
    assert "A," in out
    assert "B," in out


def test_collapse_pubcrate_leaves_other_text_alone():
    text = (
        "// comment\n"
        "fn foo() {}\n"
        "pub(crate) use bar::{\n    X,\n    Y,\n};\n"
        "fn baz() {}\n"
    )
    out = collapse_use_statements(text, kind="pubcrate")
    # Lines outside the use statement are untouched.
    assert "fn foo() {}" in out
    assert "fn baz() {}" in out
    assert "// comment" in out


def test_collapse_pub_only():
    text = "pub use crate::primitives::foo::{\n    A,\n    B,\n};\n"
    out = collapse_use_statements(text, kind="pub")
    # The whole use becomes one line.
    use_line = next(line for line in out.splitlines() if "pub use" in line)
    assert "A," in use_line
    assert "B," in use_line


def test_collapse_pub_does_not_match_pubcrate():
    text = "pub(crate) use foo::{\n    A,\n};\n"
    out = collapse_use_statements(text, kind="pub")
    # The `pub` regex does NOT match `pub(crate)` — output unchanged.
    assert out == text


def test_collapse_pubcrate_does_not_match_plain_pub():
    text = "pub use foo::{\n    A,\n};\n"
    out = collapse_use_statements(text, kind="pubcrate")
    assert out == text


def test_collapse_handles_single_line_unchanged():
    text = "pub(crate) use foo::{A, B};\n"
    out = collapse_use_statements(text, kind="pubcrate")
    assert out == text


def test_collapse_handles_multiple_use_blocks():
    text = (
        "pub(crate) use a::{\n    X,\n};\n"
        "pub(crate) use b::{\n    Y,\n};\n"
    )
    out = collapse_use_statements(text, kind="pubcrate")
    use_lines = [line for line in out.splitlines() if "pub(crate) use" in line]
    assert len(use_lines) == 2
    assert "X," in use_lines[0]
    assert "Y," in use_lines[1]
