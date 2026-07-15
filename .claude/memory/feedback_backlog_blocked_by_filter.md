---
name: feedback-backlog-blocked-by-filter
description: "When composing orchestrate tracks/backlog, apply the blocked-by exclusion per candidate — not just severity/effort + status labels"
metadata:
  node_type: memory
  type: feedback
  originSessionId: 722c53fe-2cc9-401f-87dc-66af9b098c07
---

When building a backlog for `/orchestrate tracks` (or pool/dispatch), selecting by
severity×effort and status-label exclusion is NOT enough. You MUST also apply the
**blocked-by exclusion** from `next-issue/state-format.md` § Priority Ordering:
parse each candidate's body for `Blocked by`/`Depends on`/native `blockedBy`
references and check each referenced issue's state — skip the candidate if any
blocker is still OPEN.

**Why:** On 2026-07-04 I composed 4 tracks from the `gap/presidio` feature issues
(500s) picked purely by severity×effort. 25 of 28 were blocked by open Layer-3
tracking/umbrella issues (#462–#475). Three of four dispatched golems immediately
parked at human gates having discovered their own blockers; the whole composition
had to be torn down and redone. The genuinely-unblocked high-value work was a
different set (audit issues #399–#441, vault polish #628–#640, identifier packs).

**How to apply:** Before composing, run the per-candidate blocker check
(`gh issue view <b> --json state`) and filter to unblocked issues FIRST. Tracking/
umbrella issues (titled "… tracking issue", "… roadmap", strategy-decision issues)
are usually blockers themselves, not implementation work — exclude them as heads.
Related: [[feedback-just-recipes]], [[project-presidio-audit-issues]].
