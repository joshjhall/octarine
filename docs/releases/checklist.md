# Release Checklist

The `just release` recipe automates most of the release flow. This document
records what it does for you and what's still manual.

## What `just release <type>` automates

In order:

1. **Resolves the new version** — bump keyword via
   `python3 -m scripts.release bump <type> --current <current>`, or accepts a
   literal version like `0.4.0` after parsing it through the same validator.
2. **Validates workspace member sync** — confirms `crates/octarine/Cargo.toml`
   either uses `version.workspace = true` or matches the current workspace
   version. `crates/octarine-derive/Cargo.toml` is intentionally ignored
   (independent versioning).
3. **Refuses dirty trees** — exits early if `git status --porcelain` is
   non-empty so unrelated edits don't get rolled into the release commit.
4. **Runs `just preflight-full`** — fmt-check, clippy, shellcheck,
   arch-check, all tests, and perf tests.
5. **Updates Cargo.toml versions** — root `Cargo.toml`, plus
   `crates/octarine/Cargo.toml` if it carries a literal version (skipped
   when `version.workspace = true`).
6. **Sweeps doc references** — rewrites `vX.Y.Z` → `vNEW` in:
   - `README.md`
   - `CONTRIBUTING.md`

   The list is intentionally narrow. Historical references (e.g. "Complete
   as of vX.Y.Z" in `docs/architecture/refactor-plan.md`) and doctest
   examples in `crates/octarine/src/**/*.rs` are **not** rewritten — those
   are statements about a specific past version, not pointers to "current".
7. **Regenerates `Cargo.lock`** via `cargo check --workspace --quiet`.
8. **Generates the CHANGELOG entry** — parses conventional-commit prefixes
   from `git log <prev-tag>..HEAD` into `Added / Fixed / Changed /
   Documentation / Testing / Performance / CI / Build / Other` sections.
   Prepends an HTML comment marker `<!-- TODO: review and curate before
   push -->` so the operator sees it in the diff. See
   [`changelog-format.md`](changelog-format.md) for the schema.
9. **Commits as `release: vX.Y.Z`** — staging Cargo.toml, Cargo.lock,
   CHANGELOG.md, and any of the 5 doc files that changed. Retries once if
   lefthook reformats.
10. **Tags `vX.Y.Z`** — annotated tag with message `Release vX.Y.Z`.

## What you do manually

### Before pushing

1. **Review the new CHANGELOG entry**. The auto-generated section is a
   starting point — it captures *what* changed but not *why* it matters
   for downstream callers. Curate:
   - Drop or merge purely-internal commits a downstream caller wouldn't
     care about (clippy lint sweeps, internal refactors with no API delta)
   - Group multi-PR features into a single bullet
   - Annotate breaking changes explicitly with **BREAKING:** prefix
   - Remove the `<!-- TODO: review and curate before push -->` marker
2. **Amend** if you curated:
   ```bash
   git add CHANGELOG.md
   git commit --amend --no-edit
   git tag -d vX.Y.Z && git tag -a vX.Y.Z -m "Release vX.Y.Z"
   ```

### Push

```bash
git push                    # commit
git push --tags             # the annotated tag — easy to forget
```

A bare `git push` ships the commit but not the tag, so `gh release create`
will fail with "tag does not exist" until you push tags.

### GitHub release

```bash
gh release create vX.Y.Z [--prerelease] --generate-notes
```

Use `--prerelease` for any version with a `-` suffix (alpha/beta/rc).
`--generate-notes` writes the GitHub release body from the same commit
range; you can edit it via the web UI afterwards.

## Recommended pre-merge dry run

Before merging changes to the release recipe itself (i.e. this PR), do a
full dry run on a scratch branch:

```bash
git checkout -b release-dry-run
just release patch          # or whichever keyword path you want to exercise
git log -1                  # confirm release commit
git tag -l --points-at HEAD # confirm tag

# Undo:
git reset --hard <prev-tag>
git tag -d v<new-version>
git checkout main
git branch -D release-dry-run
```

This catches Cargo.lock churn, lefthook surprises, or doc-sweep regex
issues without polluting the real history.

## Known limitations

These are out of scope for the current release recipe and are tracked as
future work:

- **Doctest version strings** in `crates/octarine/src/**/*.rs` (e.g.
  `version = "0.2"` in `crypto/validation/mod.rs`,
  `observe/tracing/otel.rs`, `testing/mod.rs`) reference major.minor only
  and don't follow the `vX.Y.Z` pattern the doc sweep handles. They go
  stale silently. Fix manually until a future Phase rewrites them by
  pattern.
- **Historical references** (e.g. `docs/architecture/refactor-plan.md`'s
  "Complete as of vX.Y.Z" header) are intentionally not rewritten — they're
  factual statements about when something happened, not "current version"
  pointers. Edit manually if their meaning changes.
- **`crates/octarine-derive`** versions independently. Bumping the workspace
  does not touch it. Coordinate manually if the two crates need a coupled
  release.
- **`cargo publish`** to crates.io is not yet automated. Octarine is git-
  dependency-only at present.
- **Recipe pause for CHANGELOG curation** — the recipe does not pause
  between writing the CHANGELOG and tagging. The TODO marker is the prompt
  to review-and-amend before push, not before tag.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ERROR: Working tree is not clean` | Uncommitted edits | `git stash` or commit first |
| `ERROR: '<x>' is neither a version nor a bump keyword` | Typo in argument | Use `major\|minor\|patch\|beta\|rc` or a literal `X.Y.Z` |
| `ERROR: crates/octarine/Cargo.toml version is out of sync` | Member crate drifted | Edit `crates/octarine/Cargo.toml` to match workspace before retrying |
| `release: Cannot bump rc from stable` | Tried `rc` from a non-prerelease | Cut a beta first: `just release beta` |
| `release: Cannot bump rc from <alpha>` | Skipping the beta cycle | Promote `alpha → beta` first |
| Lefthook reformats during commit | Trailing newline / formatting hook | Recipe retries once automatically |
| `git push --tags` fails with auth | SSH key not loaded | `ssh-add ~/.ssh/<key>` then retry |
