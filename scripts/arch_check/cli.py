"""Architecture enforcement CLI for octarine.

Mirrors `scripts/arch-check.sh` byte-for-byte on the live tree. See plan in
issue #123 for parity decisions (Check 2 multi-line bug preserved; Check 6
emits no `:line` suffix).
"""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path
from typing import Sequence

from scripts.arch_check.checks import CHECK_ORDER, CHECKS
from scripts.arch_check.core import Finding, format_finding, repo_root


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="arch_check",
        description=(
            "Architecture enforcement checks for octarine. "
            "By default runs all checks on all .rs files in crates/octarine/src."
        ),
    )
    parser.add_argument(
        "--staged-only",
        action="store_true",
        help="Only check files in the git staging area (ACMR diff filter).",
    )
    parser.add_argument(
        "checks",
        nargs="*",
        choices=CHECK_ORDER,
        metavar="CHECK",
        help=(
            "One or more checks to run. If omitted, all checks run. "
            f"Available: {', '.join(CHECK_ORDER)}"
        ),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    selected = args.checks or CHECK_ORDER
    root = repo_root()

    errors = 0
    warnings = 0

    for name in CHECK_ORDER:
        if name not in selected:
            continue
        runner = CHECKS[name]
        try:
            findings = list(runner(staged_only=args.staged_only, root=root))
        except Exception:
            # Bash uses `set -uo pipefail` without `-e` — a failure in one
            # check must not abort the others. Log to stderr and continue.
            print(f"arch-check: internal error in '{name}' check:", file=sys.stderr)
            traceback.print_exc()
            continue

        for f in findings:
            print(format_finding(f))
            if f.severity == "ERROR":
                errors += 1
            else:
                warnings += 1

    if errors > 0 or warnings > 0:
        print()
        print(f"arch-check: {errors} error(s), {warnings} warning(s)")

    return 1 if errors > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
