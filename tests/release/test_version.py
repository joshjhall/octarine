"""Tests for the version state machine."""

from __future__ import annotations

import pytest

from scripts.release.version import Prerelease, Version, VersionError, bump, parse


# ─── parse / format round-trip ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "s",
    [
        "0.0.0",
        "0.2.0",
        "1.0.0",
        "0.3.0-alpha.1",
        "0.3.0-beta.1",
        "0.3.0-beta.42",
        "0.3.0-rc.1",
        "10.20.30-beta.7",
    ],
)
def test_parse_format_roundtrip(s: str) -> None:
    assert parse(s).format() == s


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "v0.2.0",
        "0.2",
        "0.2.0.0",
        "0.2.0-",
        "0.2.0-beta",
        "0.2.0-beta.x",
        "0.2.0-rc.0.1",
        "0.2.0-snapshot.1",
        "0.2.0+build.1",  # build metadata not supported
    ],
)
def test_parse_rejects_malformed(bad: str) -> None:
    with pytest.raises(VersionError):
        parse(bad)


# ─── stable → all 5 bump kinds ──────────────────────────────────────────────


def test_bump_patch_from_stable() -> None:
    assert bump(parse("0.2.0"), "patch").format() == "0.2.1"


def test_bump_minor_from_stable() -> None:
    assert bump(parse("0.2.0"), "minor").format() == "0.3.0"


def test_bump_minor_from_stable_resets_patch() -> None:
    assert bump(parse("0.2.5"), "minor").format() == "0.3.0"


def test_bump_major_from_stable() -> None:
    assert bump(parse("0.3.0"), "major").format() == "1.0.0"


def test_bump_major_resets_minor_and_patch() -> None:
    assert bump(parse("1.4.7"), "major").format() == "2.0.0"


def test_bump_beta_from_stable_initializes_at_1() -> None:
    assert bump(parse("0.3.0"), "beta").format() == "0.3.0-beta.1"


def test_bump_rc_from_stable_is_error() -> None:
    with pytest.raises(VersionError, match="requires a prior prerelease"):
        bump(parse("0.3.0"), "rc")


# ─── prerelease finalize on patch / minor ───────────────────────────────────


def test_bump_patch_from_prerelease_finalizes() -> None:
    assert bump(parse("0.3.0-beta.3"), "patch").format() == "0.3.0"


def test_bump_minor_from_prerelease_finalizes() -> None:
    assert bump(parse("0.3.0-beta.3"), "minor").format() == "0.3.0"


def test_bump_patch_from_rc_finalizes() -> None:
    assert bump(parse("0.3.0-rc.2"), "patch").format() == "0.3.0"


def test_bump_minor_from_alpha_finalizes() -> None:
    assert bump(parse("0.4.0-alpha.5"), "minor").format() == "0.4.0"


def test_bump_major_from_prerelease_advances() -> None:
    # Major always advances regardless of prerelease state.
    assert bump(parse("0.3.0-beta.3"), "major").format() == "1.0.0"


# ─── beta state machine ─────────────────────────────────────────────────────


def test_bump_beta_increments() -> None:
    assert bump(parse("0.3.0-beta.3"), "beta").format() == "0.3.0-beta.4"


def test_bump_beta_from_alpha_resets_to_1() -> None:
    # Promoting alpha → beta starts the beta count fresh.
    assert bump(parse("0.3.0-alpha.7"), "beta").format() == "0.3.0-beta.1"


def test_bump_beta_from_rc_is_error() -> None:
    with pytest.raises(VersionError, match="regression"):
        bump(parse("0.3.0-rc.1"), "beta")


# ─── rc state machine ───────────────────────────────────────────────────────


def test_bump_rc_from_beta_resets_to_1() -> None:
    assert bump(parse("0.3.0-beta.5"), "rc").format() == "0.3.0-rc.1"


def test_bump_rc_increments() -> None:
    assert bump(parse("0.3.0-rc.2"), "rc").format() == "0.3.0-rc.3"


def test_bump_rc_from_alpha_is_error() -> None:
    with pytest.raises(VersionError, match="alpha"):
        bump(parse("0.3.0-alpha.1"), "rc")


# ─── unknown kind ───────────────────────────────────────────────────────────


def test_bump_unknown_kind_raises() -> None:
    with pytest.raises(VersionError):
        bump(parse("0.3.0"), "snapshot")  # type: ignore[arg-type]


# ─── invariant: format always parses back ──────────────────────────────────


@pytest.mark.parametrize(
    "current,kind",
    [
        ("0.2.0", "patch"),
        ("0.2.0", "minor"),
        ("0.2.0", "major"),
        ("0.2.0", "beta"),
        ("0.3.0-beta.3", "patch"),
        ("0.3.0-beta.3", "beta"),
        ("0.3.0-beta.3", "rc"),
        ("0.3.0-rc.1", "rc"),
        ("0.3.0-alpha.1", "beta"),
    ],
)
def test_bump_output_is_valid_version(current: str, kind: str) -> None:
    new = bump(parse(current), kind)  # type: ignore[arg-type]
    # Round-trip via parse to confirm the format string is well-formed.
    assert parse(new.format()).format() == new.format()


# ─── construction sanity ────────────────────────────────────────────────────


def test_version_format_with_prerelease() -> None:
    v = Version(0, 3, 0, Prerelease("beta", 1))
    assert v.format() == "0.3.0-beta.1"


def test_version_format_stable() -> None:
    assert Version(1, 2, 3).format() == "1.2.3"
