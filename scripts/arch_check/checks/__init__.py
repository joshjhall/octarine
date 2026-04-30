"""Registry of architecture checks for arch_check CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterator

from scripts.arch_check.core import Finding, iter_files
from scripts.arch_check.checks import (
    builder_visibility,
    layer_boundary,
    naming_prefix,
    naming_return_type,
    test_lint,
    type_visibility,
    unwrapped_fn,
)

CheckRunner = Callable[..., Iterator[Finding]]


def _run_layer_boundary(*, staged_only: bool, root: Path) -> Iterator[Finding]:
    files = iter_files(subdir="primitives", staged_only=staged_only, root=root)
    yield from layer_boundary.run(files=files, root=root)


def _run_unwrapped_fn(*, staged_only: bool, root: Path) -> Iterator[Finding]:
    files = iter_files(subdir=None, staged_only=staged_only, root=root)
    yield from unwrapped_fn.run(files=files, root=root)


def _run_test_lint(*, staged_only: bool, root: Path) -> Iterator[Finding]:
    files = iter_files(subdir=None, staged_only=staged_only, root=root)
    yield from test_lint.run(files=files, root=root)


def _run_naming_prefix(*, staged_only: bool, root: Path) -> Iterator[Finding]:
    yield from naming_prefix.run(staged_only=staged_only, root=root)


def _run_naming_return_type(*, staged_only: bool, root: Path) -> Iterator[Finding]:
    yield from naming_return_type.run(staged_only=staged_only, root=root)


def _run_type_visibility(*, staged_only: bool, root: Path) -> Iterator[Finding]:
    yield from type_visibility.run(staged_only=staged_only, root=root)


def _run_builder_visibility(*, staged_only: bool, root: Path) -> Iterator[Finding]:
    # staged_only intentionally ignored (matches bash).
    yield from builder_visibility.run(root=root)


# Order matters: bash executes checks in this exact sequence.
CHECK_ORDER: list[str] = [
    "layer-boundary",
    "unwrapped-fn",
    "naming-prefix",
    "naming-return-type",
    "test-lint",
    "type-visibility",
    "builder-visibility",
]

CHECKS: dict[str, CheckRunner] = {
    "layer-boundary": _run_layer_boundary,
    "unwrapped-fn": _run_unwrapped_fn,
    "naming-prefix": _run_naming_prefix,
    "naming-return-type": _run_naming_return_type,
    "test-lint": _run_test_lint,
    "type-visibility": _run_type_visibility,
    "builder-visibility": _run_builder_visibility,
}
