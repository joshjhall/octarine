# Releases

Release process documentation for octarine.

## Contents

- [`versioning.md`](versioning.md) — How to pick a bump type. Decision tree
  with worked examples from the project's tag history.
- [`checklist.md`](checklist.md) — What `just release` does for you and what
  you do manually before/after. The operator-facing reference.
- [`changelog-format.md`](changelog-format.md) — Section schema, conventional-
  commit prefix mapping, and the auto-generate-then-curate workflow.

## Quick reference

```bash
just release-preview <type>      # Read-only smoke test
just release <type>              # Real release: preflight, bump, tag
git push && git push --tags
gh release create v<X.Y.Z> [--prerelease] --generate-notes
```

Where `<type>` is one of `major | minor | patch | beta | rc` (computed) or a
literal version like `0.4.0` or `0.4.0-beta.1`.

## See also

- [`.claude/skills/octarine-release/`](../../.claude/skills/octarine-release/)
  — The release skill (versioning policy, breaking-change catalog).
- [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md) — SemVer policy summary
  for contributors.
- [`../../CHANGELOG.md`](../../CHANGELOG.md) — Release history.
- [`../architecture/layer-architecture.md`](../architecture/layer-architecture.md)
  — Defines the public-API surface (Layer 3 modules) used by the breaking-
  change catalog.
