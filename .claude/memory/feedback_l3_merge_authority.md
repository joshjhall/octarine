---
name: feedback-l3-merge-authority
description: At L3 the orchestrator must NOT merge golem PRs — surface green+clean PRs for the human to merge
metadata:
  node_type: memory
  type: feedback
  originSessionId: 722c53fe-2cc9-401f-87dc-66af9b098c07
---

At autonomy **L3**, the orchestrator (this session) must **not** run `gh pr merge`
on a golem's PR. Merging an agent-authored PR with `reviewDecision: none` is
self-approval bypassing two-party review — that authority is L4-only, and even L4
is subject to the merge invariant (green CI + clean review). The auto-mode
classifier correctly blocks it (`[Self-Approval]`).

"Auto-drive routine gates" (operator-authorized) covers **git push** and
**gh pr create** — NOT merge. Merge of a green+clean golem PR is left to a human:
the orchestrator surfaces the PR (number, CI, review) and the human runs
`gh pr merge` / clicks merge. This is the documented topology — "the orchestrator
never merges golem branches into its own; the humans in the loop merge anything a
golem leaves for them."

**Why:** On 2026-07-04 I treated merge as an auto-drivable routine gate and tried
`gh pr merge 671` at L3; the classifier denied it (self-approval, no two-party
review). The operator confirmed: humans merge golem PRs. The golem's own
`/ship-issue` adversarial review is NOT a GitHub approval.

**How to apply:** In monitor sweeps, when a golem PR is green+clean, report it as
"awaiting human merge" with the `gh pr merge <N> --squash --delete-branch` command
for the operator — do not run it. Only after the human merges does lane-aware
refill dispatch the track's next issue. Related: [[feedback-backlog-blocked-by-filter]].
