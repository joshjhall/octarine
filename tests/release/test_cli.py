"""Tests for the release CLI."""

from __future__ import annotations

import io
import sys
from typing import Sequence

import pytest

from scripts.release.cli import main


def _run(argv: Sequence[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    rc = main(list(argv))
    captured = capsys.readouterr()
    return rc, captured.out.strip(), captured.err.strip()


def test_bump_prints_new_version(capsys: pytest.CaptureFixture[str]) -> None:
    rc, out, err = _run(["bump", "patch", "--current", "0.2.0"], capsys)
    assert rc == 0
    assert out == "0.2.1"
    assert err == ""


def test_bump_finalizes_prerelease(capsys: pytest.CaptureFixture[str]) -> None:
    rc, out, _ = _run(["bump", "patch", "--current", "0.3.0-beta.3"], capsys)
    assert rc == 0
    assert out == "0.3.0"


def test_bump_beta_increment(capsys: pytest.CaptureFixture[str]) -> None:
    rc, out, _ = _run(["bump", "beta", "--current", "0.3.0-beta.3"], capsys)
    assert rc == 0
    assert out == "0.3.0-beta.4"


def test_bump_rc_from_stable_errors(capsys: pytest.CaptureFixture[str]) -> None:
    rc, out, err = _run(["bump", "rc", "--current", "0.3.0"], capsys)
    assert rc == 1
    assert out == ""
    assert "requires a prior prerelease" in err


def test_bump_rejects_invalid_current(capsys: pytest.CaptureFixture[str]) -> None:
    rc, out, err = _run(["bump", "patch", "--current", "not.a.version"], capsys)
    assert rc == 1
    assert out == ""
    assert "Invalid version" in err


def test_parse_validates_well_formed(capsys: pytest.CaptureFixture[str]) -> None:
    rc, out, _ = _run(["parse", "0.3.0-beta.1"], capsys)
    assert rc == 0
    assert out == "0.3.0-beta.1"


def test_parse_rejects_malformed(capsys: pytest.CaptureFixture[str]) -> None:
    rc, out, err = _run(["parse", "v0.2.0"], capsys)
    assert rc == 1
    assert "Invalid version" in err


def test_unknown_subcommand_exits_nonzero(capsys: pytest.CaptureFixture[str]) -> None:
    # argparse handles this — `required=True` on the subcommand should reject.
    with pytest.raises(SystemExit):
        main([])
