---
name: project-new-crate-ci-gates
description: "Adding a workspace crate breaks SemVer CI (no baseline in origin/main) and needs registration in sites the crate-layout checklist omits"
metadata:
  node_type: memory
  type: project
---

Adding a new workspace member (first done for `crates/octarine-llm`, #520)
fails CI in a way the `docs/architecture/crate-layout.md` registration checklist
does not predict:

**SemVer job fails, and it is not your code.** `cargo semver-checks
check-release --workspace --baseline-rev origin/main` exits **101**
("could not complete") for a crate that does not exist in the baseline
revision — there is no prior API to diff. It does *not* report no-change.
Fix: `--exclude <new-crate>` in the `semver-check` recipe, with a comment to
drop it once the crate lands on main. A bootstrap workaround, not a permanent
opt-out.

**Two registration sites the checklist omits:**

1. `lefthook.yml` duplicates the justfile's hardcoded `cargo machete` crate
   list. Update both or machete silently skips the new crate.
2. `justfile` release has **four** per-crate sites (version-sync guards,
   version-bump `sed`, workspace-deps `sed`, and the **git-add file list**),
   plus `release-preview` mirroring them. Missing the git-add site silently
   drops the new manifest from the release commit.

Also: the release-completion echo and `release.yml`'s header comment both said
"all three crates" — grep for the count spelled out, and note the justfile one
**spans two lines**, so `grep 'all three crates'` misses it.

`.conform.yaml` needed no edit — `^llm$` was already present.

Related: [[project_conform_scope_allowlist]], [[project_release_generator_and_gates]]
