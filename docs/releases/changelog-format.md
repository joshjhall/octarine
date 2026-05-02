# CHANGELOG Format

Octarine's `CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/)
section conventions, with section names tuned for the project's commit
prefix taxonomy. The `just release` recipe auto-generates a draft entry from
git history; the operator curates it before push.

## Entry shape

```markdown
## [VERSION] - YYYY-MM-DD

<!-- TODO: review and curate before push -->

### Added

- feat(scope): summary (#123)

### Fixed

- fix(scope): summary (#124)

### Changed

- refactor(scope): summary (#125)
- chore(deps): summary

### Documentation

- docs(scope): summary

### Testing

- test(scope): summary

### Performance

- perf(scope): summary

### CI

- ci: summary

### Build

- build: summary

### Other

- summary  # commits without a recognized prefix
```

Sections are emitted in the order above and only appear when they have
content. Within a section, commits stay in the order returned by
`git log <prev-tag>..HEAD --oneline`.

## Conventional-commit prefix mapping

| Prefix | Section |
|---|---|
| `feat` | Added |
| `fix` | Fixed |
| `refactor` | Changed |
| `chore` | Changed |
| `docs` | Documentation |
| `test` | Testing |
| `perf` | Performance |
| `ci` | CI |
| `build` | Build |
| (anything else not matching `release:`) | Other |

`release:` commits (the previous release's own commit) are filtered out so
they don't appear in the next entry.

## Auto-generate then curate

The recipe writes a section bullet for **every** commit in the range that
matches a known prefix. This is intentionally over-inclusive — better to
trim than to miss something. Before `git push`:

1. **Drop noise**: clippy fix-ups, lint sweeps, single-character doc
   tweaks, internal refactors with no API delta.
2. **Group**: a feature delivered across N commits should usually be one
   bullet, not N. Reference the umbrella issue or the final commit.
3. **Mark breaking changes**: prefix the bullet with `**BREAKING:**` so
   downstream readers can find them with one grep. Add a brief migration
   note below if non-obvious.
4. **Remove the TODO marker**: `<!-- TODO: review and curate before push -->`
   should not survive into a pushed release.

Example of curated output:

```markdown
## [0.4.0] - 2026-06-15

### Added

- **BREAKING:** new `IdentifierType::Ein` variant — exhaustive `match`
  arms over `IdentifierType` must be updated. (#239)
- New PII scanner for hostnames and ports (#291)

### Changed

- **BREAKING:** rand 0.9 → 0.10 propagates to public API: `RngCore` is
  now imported as `rand_core::Rng`. Callers using `rand::Rng` directly
  must switch to `rand::RngExt`. (#277-281)

### Fixed

- URL query strings now redacted in observability logs (#241)
- Plaintext token buffers zeroized on auth reset (#270)
```

Compared to the raw auto-generated entry, this:
- Combined 5 dependabot bumps into a single bullet
- Added explicit migration notes for the rand 0.10 break
- Marked the IdentifierType variant as breaking (it is — exhaustive matches)
- Dropped routine refactor / test / build commits the recipe would otherwise
  list

## Section order rationale

`Added` first because new features are what most readers look for. `Fixed`
second because regressions on existing functionality are the next-most
actionable. `Changed` covers internal refactors plus dependency bumps —
it's where breaking changes most often land, hence the `**BREAKING:**`
discipline. `Documentation / Testing / Performance / CI / Build` follow in
descending caller relevance. `Other` is a fall-through for unconventional
prefixes; treat it as a signal to amend the prefix mapping if the same
prefix shows up repeatedly.

## See also

- [`versioning.md`](versioning.md) — how to pick the bump type that
  goes in the entry header
- [`checklist.md`](checklist.md) — full release flow including curation step
- [`../../CHANGELOG.md`](../../CHANGELOG.md) — the actual log
