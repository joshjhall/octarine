"""CHANGELOG section extraction for release automation.

The release workflow uses `extract(version)` to pull the matching
`## [VERSION] - DATE` block out of `CHANGELOG.md` and emit it as the
GitHub Release body. The extractor strips the operator-only
`<!-- TODO: review and curate before push -->` marker that `just release`
prepends as a curation prompt — it would be confusing in a published
release body.
"""

from __future__ import annotations

from pathlib import Path


class ChangelogError(Exception):
    """Raised when a CHANGELOG section cannot be located or parsed."""


# Operator-only marker inserted by `just release` for human curation. The
# extractor strips it so it never appears in a published GitHub Release.
_TODO_MARKER = "<!-- TODO: review and curate before push -->"


def extract(version: str, changelog: Path | str = Path("CHANGELOG.md")) -> str:
    """Return the CHANGELOG body for `version`.

    Locates the line `## [VERSION] - DATE` and returns everything up to (but
    not including) the next `## ` heading, stripped of leading/trailing blank
    lines and the curation TODO marker.

    Raises `ChangelogError` if the file is missing or the section is absent.
    """
    path = Path(changelog)
    if not path.exists():
        raise ChangelogError(f"CHANGELOG not found at {path}")

    needle = f"## [{version}]"
    in_section = False
    captured: list[str] = []

    for line in path.read_text(encoding="utf-8").splitlines():
        if in_section:
            # Stop at the next top-level section (either another version
            # or the [Unreleased] header — both start with "## ").
            if line.startswith("## "):
                break
            captured.append(line)
            continue
        if line.startswith(needle):
            in_section = True

    if not in_section:
        raise ChangelogError(f"No section for version {version!r} in {path}")

    body = "\n".join(captured).strip("\n")
    # Strip the operator-only TODO marker (and its trailing blank line).
    body = body.replace(_TODO_MARKER + "\n\n", "").replace(_TODO_MARKER + "\n", "")
    body = body.replace(_TODO_MARKER, "")
    return body.strip("\n")
