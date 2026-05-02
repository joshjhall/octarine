---
description: Octarine release process — semantic versioning policy, bump-type rules, and `just release` usage. Use when cutting a release, picking a version bump (major/minor/patch/beta/rc), or auditing a change to decide whether it requires a breaking-version bump.
---

# Octarine Release

The release pipeline lives in two places: the `just release` recipe in the
project root `justfile` (orchestration) and `scripts/release/` (the
semver state machine that drives bump keywords). This skill is the policy
half — when to pick which bump type, what counts as a breaking change in a
security library, and how the alpha → beta → rc → stable lifecycle is
enforced. See `docs/releases/` for the operator-facing reference.

## Pre-1.0 SemVer Policy

Octarine is on `0.x` and not yet published to crates.io. While we're pre-1.0,
we follow the [Cargo SemVer convention](https://doc.rust-lang.org/cargo/reference/semver.html)
for `0.y.z`:

| Version part | Meaning while 0.x | After 1.0 |
|---|---|---|
| `0.X.0` (minor) | Breaking change OR new feature | New backwards-compatible feature |
| `0.X.Y` (patch) | Backwards-compatible change (bugfix, doc, internal) | Bugfix only |
| `1.0.0` | First stable release | First major bump after stable |

Every breaking change **must** be recorded in `CHANGELOG.md` under the
release entry, with enough context that downstream callers can adjust.

## Bump Types

| Keyword | Formula | When to use |
|---|---|---|
| `patch` | `0.X.Y` → `0.X.(Y+1)`; from prerelease, **finalize** to `0.X.Y` | Bugfix, doc-only change, internal refactor with no public API delta |
| `minor` | `0.X.Y` → `0.(X+1).0`; from prerelease, **finalize** to `0.X.Y` | New feature OR breaking change while 0.x |
| `major` | `X.Y.Z` → `(X+1).0.0` (always advances) | Breaking change after 1.0; intentional "we're stable now" 0.x → 1.0 |
| `beta` | stable → `X.Y.Z-beta.1`; alpha → `X.Y.Z-beta.1`; beta → `beta.(N+1)` | Feature-complete prerelease for downstream testing |
| `rc` | `X.Y.Z-beta.N` → `X.Y.Z-rc.1`; rc → `rc.(N+1)` | Final validation candidate, no further changes expected |

**Finalize semantics**: from `0.3.0-beta.3`, both `patch` and `minor` produce
`0.3.0`. The beta becomes the stable release. This avoids skipping the
stable line entirely (e.g. `0.3.0-beta.3 → 0.3.1` would mean "0.3.0 never
shipped"). Use `major` or a literal version if you want different behavior.

## Breaking Change Catalog

Octarine's public API surface is **Layer 3**: the eight `pub` modules
`identifiers/`, `data/`, `security/`, `runtime/`, `crypto/`, `auth/`, `http/`,
`io/`. Layer 1 (`primitives/`) is `pub(crate)` and Layer 2 (`observe/`) is
public but its breaking changes also count. See
`docs/architecture/layer-architecture.md`.

Breaking changes (require minor bump while 0.x, major bump after 1.0):

- Removing or renaming any public function, struct, enum, trait, or module
  in Layer 2 or Layer 3
- Adding a required parameter to a public Builder method or shortcut
- Adding a non-`#[non_exhaustive]` field or variant to a public struct/enum
- Changing visibility from `pub` to `pub(crate)` (or removing a re-export)
- Tightening validation defaults (e.g. rejecting a previously-accepted
  pattern in a `validate_*` function) — even when "more secure"
- Changing detection semantics so that `is_*` returns `false` for inputs
  that previously returned `true`, or vice versa, in ways callers depend on
- Removing a feature flag

**Not breaking** (patch is fine):

- Adding new public API (additive)
- Adding fields/variants to a `#[non_exhaustive]` type
- Internal refactors below `pub(crate)`
- Behavior changes that fix incorrect output (genuine bugfix)
- Adding a new feature flag (default-off)

When in doubt, run `cargo semver-checks check-release --workspace
--baseline-rev origin/main` — it catches the structural cases mechanically.

## Beta vs RC Promotion

The state machine enforces a strict forward-only lifecycle:

```
        beta ───────► rc ───────► (finalize via patch/minor)
        ▲
        │
       alpha                    stable
```

Errors raised by `python3 -m scripts.release bump`:

- `rc` from stable: requires a prior prerelease (use `beta` first)
- `beta` from `rc`: regression (would walk backward in the lifecycle)
- `rc` from `alpha`: must promote `alpha → beta` first

Stable is reached by `patch` or `minor` from any prerelease, never by `rc`
directly.

## How to Release

Happy path:

```bash
just release-preview <type>      # Read-only smoke test — proposed version,
                                 # doc files to rewrite, commits since last tag

just release <type>              # Run preflight-full, bump versions, sweep
                                 # doc references, generate CHANGELOG, commit,
                                 # tag

# Review the new CHANGELOG entry — look for the "TODO: review" marker.
# Amend the commit if curation is needed.

git push && git push --tags
gh release create vX.Y.Z [--prerelease] --generate-notes
```

See `docs/releases/checklist.md` for the full step-by-step.

## Common Mistakes

- **`rc` from stable**: nothing to promote. The state machine errors.
  Cut a beta first.
- **Forgetting `git push --tags`**: a bare `git push` ships the commit but
  not the tag, so `gh release create` will fail.
- **Manually editing `crates/octarine-derive/Cargo.toml`**: the derive crate
  is intentionally on independent versioning. The release recipe never
  touches it.
- **Skipping `release-preview`**: the keyword bumps look obvious until they
  aren't (e.g. `minor` from a prerelease finalizes — surprising the first
  time). Preview to confirm.
- **Mass-editing CHANGELOG entries after tag**: amending the release commit
  works only before push. After push, follow up with a plain `chore(docs):`
  commit.

## Verification

- `just release-preview <type>` — read-only; never mutates the tree
- `just release-test` — pytest matrix for the version state machine
- `cargo semver-checks check-release --workspace --baseline-rev origin/main`
  — mechanical breaking-change detection on the public API
- Throwaway-branch dry run (recommended before adopting a new bump type):
  on a scratch branch, run `just release patch`, inspect the result, then
  `git reset --hard <prev-tag> && git tag -d v<new>` to undo

## When to Use

- Cutting any release (literal version or keyword bump)
- Deciding whether a PR needs a minor or patch bump while 0.x
- Authoring a CHANGELOG entry (section schema lives in
  `docs/releases/changelog-format.md`)
- Reviewing a PR for SemVer compliance — does it tighten validation? add
  a required parameter? remove a re-export?

## When NOT to Use

- Day-to-day commits (no release context)
- `octarine-derive` versioning — that crate is independently versioned and
  not in scope here
- Publishing to crates.io — not yet automated; track separately
