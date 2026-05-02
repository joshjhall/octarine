"""Semantic versioning state machine for octarine releases.

Holds the pure version-arithmetic that powers `just release <type>`. Keeping
this in Python (rather than inline bash + sed) gives us a tested,
auditable transition table for the alpha → beta → rc → stable lifecycle.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

PrereleaseKind = Literal["alpha", "beta", "rc"]
BumpKind = Literal["major", "minor", "patch", "beta", "rc"]

# X.Y.Z or X.Y.Z-{alpha|beta|rc}.N — matches the format the existing
# `release` recipe accepts.
_VERSION_RE = re.compile(
    r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"(?:-(?P<kind>alpha|beta|rc)\.(?P<n>\d+))?$"
)


class VersionError(ValueError):
    """Raised when a version string or bump operation is invalid."""


@dataclass(frozen=True)
class Prerelease:
    kind: PrereleaseKind
    n: int


@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int
    prerelease: Prerelease | None = None

    def format(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease is None:
            return base
        return f"{base}-{self.prerelease.kind}.{self.prerelease.n}"


def parse(s: str) -> Version:
    """Parse a version string into a `Version`.

    Raises `VersionError` on anything that doesn't match
    `X.Y.Z` or `X.Y.Z-{alpha|beta|rc}.N`.
    """
    m = _VERSION_RE.match(s)
    if m is None:
        raise VersionError(
            f"Invalid version {s!r}: expected X.Y.Z or X.Y.Z-{{alpha,beta,rc}}.N"
        )
    pre: Prerelease | None = None
    if m.group("kind") is not None:
        pre = Prerelease(kind=m.group("kind"), n=int(m.group("n")))
    return Version(
        major=int(m.group("major")),
        minor=int(m.group("minor")),
        patch=int(m.group("patch")),
        prerelease=pre,
    )


def bump(v: Version, kind: BumpKind) -> Version:
    """Compute the next version given a bump kind.

    Octarine's release lifecycle (pre-1.0):
    - `patch` / `minor` from a prerelease finalize the in-progress version
      (e.g. 0.3.0-beta.3 + patch → 0.3.0). On a stable input, they advance
      normally.
    - `major` always advances and resets minor/patch/prerelease.
    - `beta` initializes from stable or alpha, increments from beta. Going
      from rc back to beta is a regression (raises VersionError).
    - `rc` requires a prior beta; promotes beta → rc.1 or increments rc.
      rc-from-stable and alpha→rc are errors (callers must promote
      alpha→beta first).
    """
    if kind == "major":
        return Version(major=v.major + 1, minor=0, patch=0, prerelease=None)

    if kind == "minor":
        if v.prerelease is None:
            return Version(major=v.major, minor=v.minor + 1, patch=0, prerelease=None)
        # Finalize the in-progress minor: drop the prerelease tag.
        return Version(major=v.major, minor=v.minor, patch=v.patch, prerelease=None)

    if kind == "patch":
        if v.prerelease is None:
            return Version(
                major=v.major, minor=v.minor, patch=v.patch + 1, prerelease=None
            )
        return Version(major=v.major, minor=v.minor, patch=v.patch, prerelease=None)

    if kind == "beta":
        if v.prerelease is None:
            return Version(
                major=v.major,
                minor=v.minor,
                patch=v.patch,
                prerelease=Prerelease("beta", 1),
            )
        if v.prerelease.kind == "alpha":
            return Version(
                major=v.major,
                minor=v.minor,
                patch=v.patch,
                prerelease=Prerelease("beta", 1),
            )
        if v.prerelease.kind == "beta":
            return Version(
                major=v.major,
                minor=v.minor,
                patch=v.patch,
                prerelease=Prerelease("beta", v.prerelease.n + 1),
            )
        # rc → beta would step backward in the lifecycle.
        raise VersionError(
            f"Cannot bump beta from {v.format()}: "
            "promoting rc back to beta is a regression"
        )

    if kind == "rc":
        if v.prerelease is None:
            raise VersionError(
                f"Cannot bump rc from stable {v.format()}: "
                "rc requires a prior prerelease (use 'beta' first)"
            )
        if v.prerelease.kind == "beta":
            return Version(
                major=v.major,
                minor=v.minor,
                patch=v.patch,
                prerelease=Prerelease("rc", 1),
            )
        if v.prerelease.kind == "rc":
            return Version(
                major=v.major,
                minor=v.minor,
                patch=v.patch,
                prerelease=Prerelease("rc", v.prerelease.n + 1),
            )
        # alpha → rc would skip the beta cycle.
        raise VersionError(
            f"Cannot bump rc from {v.format()}: "
            "promote alpha → beta first"
        )

    raise VersionError(f"Unknown bump kind: {kind!r}")
