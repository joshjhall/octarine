---
name: project_release_generator_and_gates
description: "just release: changelog generator now classifies by subject (fixed 2026-09-06); the tag must be re-pointed after any amend, and CI is the real gate"
metadata:
  node_type: memory
  type: project
---

Three things about `just release` that only surface mid-release.

**The changelog generator was fixed on 2026-09-06 (commit `75d4bfe`).** It
used `git log --grep="^feat"` per prefix; `--grep` matches the whole commit
message and `^` anchors to *any line*, so a commit whose body contained a
line starting with another prefix was emitted under every section it matched
(24 commits -> 31 entries in the beta.7 range). It now classifies each commit
once from its subject (`%s`). Curation should be light — if you find yourself
hand-deduping again, the regression is in that loop.

**`just release` commits AND tags, but does not push.** If you amend the
release commit (e.g. to curate the CHANGELOG), the tag still points at the
pre-amend commit and must be moved:

```bash
git tag -f -a vX.Y.Z -m "Release vX.Y.Z"
git rev-parse vX.Y.Z^{commit}   # annotated tags print their own hash without ^{commit}
```

This matters beyond tidiness: the GitHub Release body is generated from the
CHANGELOG **at the tagged commit**, so an un-moved tag publishes the
uncurated entry. Same applies if any further commit lands before the push.

**Verify the push, don't trust the exit code.** `git push ... | tail -n` in a
background task reports *tail's* status, so a failed push can look like
`exit 0`. Check `git rev-parse origin/main` or grep the log for
`failed to push`. The pre-push hook runs the full suite and legitimately
fails releases — that is the point.

**How to apply:** prefer CI over the local hook as the release gate (it adds
Windows/macOS, `SemVer`, the strict `Doc` job, and `Coverage`, whose
instrumentation is the load condition that exposes dispatcher timing bugs —
see [[project_wallclock_ttl_test_races]]). Push `main`, wait for green, then
push the tag; the tag is what triggers the irreversible crates.io publish.
See [[feedback_just_recipes]] and [[project_ci_doc_job_strict]].
