"""CLI-level tests: argparse, dispatch, exit code, summary line, --help."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_cli(*args: str, cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "scripts.arch_check", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def test_help_exits_zero():
    result = _run_cli("--help")
    assert result.returncode == 0
    assert "Architecture enforcement checks" in result.stdout


def test_live_tree_clean_no_output_exit_zero():
    result = _run_cli()
    assert result.returncode == 0
    assert result.stdout == ""


def test_unknown_check_rejected():
    result = _run_cli("not-a-real-check")
    assert result.returncode != 0
    assert "invalid choice" in result.stderr or "invalid" in result.stderr


def test_summary_only_when_findings_present(tmp_path: Path):
    # Build a synthetic repo and run the CLI against it via PYTHONPATH override.
    src = tmp_path / "crates/octarine/src/primitives"
    src.mkdir(parents=True)
    (src / "bad.rs").write_text("use crate::observe::Foo;\n")

    # We can't redirect repo_root() from CLI args, so spawn a child python that
    # sets the cwd to tmp_path AND points sys.path so `scripts.arch_check` is
    # importable. Easier: invoke our CLI via -c with a custom main.
    # Patch `cli.repo_root` (not `core.repo_root`): `cli` imported the name
    # at module load time, so patching the module-level binding is what counts.
    code = (
        "import sys; "
        f"sys.path.insert(0, {str(REPO_ROOT)!r}); "
        "import scripts.arch_check.cli as cli; "
        f"cli.repo_root = lambda: __import__('pathlib').Path({str(tmp_path)!r}); "
        "raise SystemExit(cli.main(['layer-boundary']))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "[ERROR] layer-boundary:" in result.stdout
    assert "arch-check: 1 error(s), 0 warning(s)" in result.stdout


def test_staged_only_no_files_exits_zero():
    result = _run_cli("--staged-only")
    assert result.returncode == 0


def test_multiple_checks_run_in_order():
    # Both checks fire on the live tree → empty (clean tree).
    result = _run_cli("layer-boundary", "test-lint")
    assert result.returncode == 0
    assert result.stdout == ""
