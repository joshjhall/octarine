# Versioning

How to pick a bump type for an octarine release. Octarine is a foundation
library (security primitives + observability) and tracks SemVer discipline
closely so downstream callers can update with confidence.

## Pre-1.0 vs post-1.0

Octarine is currently `0.x` and not yet on crates.io. We follow the
[Cargo SemVer convention for `0.y.z`](https://doc.rust-lang.org/cargo/reference/semver.html):

| Pre-1.0 | Post-1.0 |
|---|---|
| **minor** = breaking change OR new feature | minor = backwards-compatible feature only |
| **patch** = backwards-compatible (bugfix, doc, internal refactor) | patch = bugfix only |
| **major** = intentional `0.x → 1.0` jump | major = breaking change |

`1.0.0` is the contract: from that point on, breaking changes require a
major bump. Don't ship `1.0` until the public API is something we're willing
to support across patch releases.

## Decision tree

```
1. Does the change alter the public API or default behavior in a way callers
   could depend on?
   → YES, see step 2
   → NO  → patch

2. Is it a removal, rename, signature change, tightened validation, or
   non-`#[non_exhaustive]` field/variant addition?
   → YES → minor (pre-1.0) or major (post-1.0)
   → NO, it's purely additive → minor (new feature; pre-1.0 still bumps minor)
```

See the breaking-change catalog in
[`.claude/skills/octarine-release/SKILL.md`](../../.claude/skills/octarine-release/SKILL.md)
for the full list. When in doubt:

```bash
cargo semver-checks check-release --workspace --baseline-rev origin/main
```

This catches the structural cases (signature changes, removed exports)
mechanically. It cannot detect semantic changes (e.g. validation now rejects
inputs it previously accepted) — those still require human judgment.

## Bump-type formulas

| Keyword | Stable input | Prerelease input |
|---|---|---|
| `patch` | `0.X.Y` → `0.X.(Y+1)` | **finalize** to `0.X.Y` |
| `minor` | `0.X.Y` → `0.(X+1).0` | **finalize** to `0.X.Y` |
| `major` | `X.Y.Z` → `(X+1).0.0` | `(X+1).0.0` (always advances) |
| `beta`  | `X.Y.Z` → `X.Y.Z-beta.1` | `beta.N` → `beta.(N+1)`; `alpha.N` → `beta.1`; `rc.N` → **error** |
| `rc`    | **error** (requires prior beta) | `beta.N` → `rc.1`; `rc.N` → `rc.(N+1)`; `alpha.N` → **error** |

**Finalize semantics**: when the current version is a prerelease and you
bump `patch` or `minor`, the result drops the prerelease tag. From
`0.3.0-beta.3`, both `patch` and `minor` produce `0.3.0` — the beta becomes
the stable release. This avoids skipping the stable line. If you actually
want `0.3.1` or `0.4.0` from a prerelease, pass the literal version.

## Worked examples (from this project's history)

| From | Action | Reason | To |
|---|---|---|---|
| `v0.2.0` | `beta` | Began the 0.3.0 prerelease cycle | `v0.3.0-beta.1` |
| `v0.3.0-beta.1` | `beta` | Iterated within beta | `v0.3.0-beta.2` |
| `v0.3.0-beta.2` | `beta` | Iterated within beta | `v0.3.0-beta.3` |
| `v0.3.0-beta.3` | `rc` (hypothetical) | Promoted to release candidate | `v0.3.0-rc.1` |
| `v0.3.0-beta.3` | `patch` (hypothetical) | Finalized the in-progress minor | `v0.3.0` |
| `v0.3.0` | `minor` (hypothetical) | New breaking change while 0.x | `v0.4.0` |
| `v0.X.Y` | `major` (eventual) | Public API stabilization | `v1.0.0` |

## When `major` makes sense pre-1.0

Bumping `0.x → 1.0` is a deliberate signal that the API surface is something
we're committing to. Don't do it just to escape `0.x` etiquette. Go to
`1.0` when:

- Layer 3 module shape is stable (no planned splits/renames)
- The naming-conventions enforcement catches all callers
- We have a real downstream consumer that wants `^1.0` semver guarantees

Until then, `0.X.Y` is the right place to be — it lets us iterate on the
public API while still being responsible about CHANGELOG entries.

## Pre-1.0 → 1.0 transition

When the time comes:

1. Cut a final beta cycle to flush downstream feedback.
2. Promote to `rc` once the candidate set is frozen.
3. Finalize via `just release minor` (or `just release 1.0.0` literally) so
   the prerelease is dropped.
4. Audit the CHANGELOG — every breaking change since `0.1.0` should be
   discoverable from a single read of the file.
5. Add a CONTRIBUTING note: post-1.0 the rules tighten (minor must be
   additive only).
