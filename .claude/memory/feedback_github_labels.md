---
name: GitHub labels required for /next-issue workflow
description: Ensure status/pr-pending exists alongside status/in-progress, status/commit-pending, status/on-hold before shipping
type: feedback
originSessionId: 62b38eb1-d94a-4b80-9d19-bda2bdac77bb
---
`/next-issue-ship` (Option 1, Branch+PR) requires a `status/pr-pending`
label on the GitHub repo. It was missing from joshjhall/octarine on
2026-04-17 — `gh issue edit` failed atomically so neither the add nor
the remove applied, leaving the issue stuck with `status/in-progress`.
Created via `gh label create "status/pr-pending" --color 0E8A16
--description "PR open and awaiting review/merge"` on 2026-04-17.

**Why:** The four status labels (`in-progress`, `pr-pending`,
`commit-pending`, `on-hold`) are all referenced in the priority-query
exclusion filter in `next-issue/state-format.md`. A missing label doesn't
cause query breakage (the `-label:` filter just matches zero items) but
it does break `--add-label` on shipping. The other three already exist.

**How to apply:** Before the first `/next-issue-ship` invocation on any
new repo, verify all four labels exist via `gh label list --search status`.
If `status/pr-pending` is missing, create it. Consider also checking
`status/commit-pending` and `status/on-hold` — they already exist here but
may be missing on other repos.
