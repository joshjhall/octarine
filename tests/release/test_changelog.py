"""Tests for the CHANGELOG section extractor."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.release.changelog import ChangelogError, extract


_SAMPLE = """\
# Changelog

All notable changes to octarine will be documented in this file.

## [Unreleased]

### Added

- feat(foo): new thing

## [0.3.0-beta.3] - 2026-04-28

<!-- TODO: review and curate before push -->

### Fixed

- fix(observe): metrics instrumentation

### Changed

- chore(deps): bundle dependabot bumps

## [0.3.0-beta.2] - 2026-04-25

### Added

- feat(identifiers): UK NINO
"""


@pytest.fixture
def changelog(tmp_path: Path) -> Path:
    f = tmp_path / "CHANGELOG.md"
    f.write_text(_SAMPLE, encoding="utf-8")
    return f


def test_extract_returns_section_body(changelog: Path) -> None:
    body = extract("0.3.0-beta.3", changelog)
    assert "### Fixed" in body
    assert "fix(observe): metrics instrumentation" in body
    assert "### Changed" in body


def test_extract_strips_todo_marker(changelog: Path) -> None:
    body = extract("0.3.0-beta.3", changelog)
    assert "TODO: review" not in body


def test_extract_stops_at_next_version(changelog: Path) -> None:
    body = extract("0.3.0-beta.3", changelog)
    assert "0.3.0-beta.2" not in body
    assert "UK NINO" not in body


def test_extract_last_section_works(changelog: Path) -> None:
    body = extract("0.3.0-beta.2", changelog)
    assert "UK NINO" in body


def test_extract_unreleased_works(changelog: Path) -> None:
    body = extract("Unreleased", changelog)
    assert "feat(foo): new thing" in body


def test_extract_missing_version_raises(changelog: Path) -> None:
    with pytest.raises(ChangelogError, match="No section for version"):
        extract("9.9.9", changelog)


def test_extract_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ChangelogError, match="CHANGELOG not found"):
        extract("0.3.0", tmp_path / "does-not-exist.md")


def test_extract_trims_trailing_blank_lines(changelog: Path) -> None:
    body = extract("0.3.0-beta.3", changelog)
    assert not body.startswith("\n")
    assert not body.endswith("\n")
