"""CLI for the release helper.

Two subcommands:

- `bump <kind> --current X.Y.Z` — print the computed next version to stdout.
  The `release` justfile recipe captures this with `$(...)` to drive
  Cargo.toml updates.
- `parse X.Y.Z` — validate a version string; exits 0 on success, non-zero
  with a message on failure. Used by `release` for literal-version input.

All errors print to stderr and exit non-zero, so failures are visible in the
recipe output without polluting the captured stdout.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from scripts.release.version import VersionError, bump, parse

BUMP_KINDS = ("major", "minor", "patch", "beta", "rc")


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="release",
        description="Compute and validate octarine release versions.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    bump_p = sub.add_parser(
        "bump",
        help="Compute the next version from a bump kind and current version.",
    )
    bump_p.add_argument("kind", choices=BUMP_KINDS, help="Bump kind.")
    bump_p.add_argument(
        "--current",
        required=True,
        help="Current version (X.Y.Z or X.Y.Z-{alpha,beta,rc}.N).",
    )

    parse_p = sub.add_parser(
        "parse",
        help="Validate a version string. Prints the canonical form on success.",
    )
    parse_p.add_argument("version", help="Version string to validate.")

    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    try:
        if args.command == "bump":
            current = parse(args.current)
            new = bump(current, args.kind)
            print(new.format())
            return 0
        if args.command == "parse":
            v = parse(args.version)
            print(v.format())
            return 0
    except VersionError as e:
        print(f"release: {e}", file=sys.stderr)
        return 1

    print(f"release: unknown command {args.command!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
