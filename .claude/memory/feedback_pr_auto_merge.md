---
name: PR auto-merge on green
description: When a PR opened via /next-issue-ship goes green, squash-merge with branch deletion and prune local refs without asking
type: feedback
originSessionId: 332028ef-8736-458e-a34d-2fedb2a3582a
---

When a PR (typically opened via `/next-issue-ship` Option 1) reports all CI
checks green, immediately:

1. `gh pr merge {N} --squash --delete-branch`
2. `git fetch --prune origin` to clear stale local tracking refs
3. Remove `status/in-progress` from the issue (the squash-merge with
   `Closes #{N}` already auto-closes it)
4. Comment on the issue with the merged-PR reference

**Why:** User explicitly stated "when ci is green, merge to main and prune
branches" and reaffirmed it as a standing rule. Asking for merge approval
on green PRs is friction; the user expects the loop to close itself.

**How to apply:** Treat this as default behavior for any PR opened in the
session via `/next-issue-ship`. Do NOT proactively merge PRs that were
opened by other workflows (manual `gh pr create`, dependabot, etc.) without
confirmation. Do NOT merge PRs flagged `severity/critical` without
confirmation, regardless of green CI.

**Environment override (observed 2026-07-15, PR #691, L4 run):** the Claude
Code **auto-mode classifier blocks the agent from `gh pr merge`-ing a PR it
authored and pushed itself** when no human review is visible — it flags the
self-approval and points at [[feedback_l3_merge_authority]] as the conflicting
signal. This is a harness-level guardrail, not something to work around. Net
effect: even on a green+clean L4 run, `gh pr merge` will be denied, so the
practical outcome collapses to "surface the green+clean PR and let the human
merge." Don't burn a retry cycle re-attempting the merge; prepare the PR fully
(green CI, `status/pr-pending`, mergeable CLEAN), then hand off the URL.
