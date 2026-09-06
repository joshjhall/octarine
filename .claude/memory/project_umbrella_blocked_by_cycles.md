---
name: project-umbrella-blocked-by-cycles
description: "Presidio child issues declare \"Blocked by\" their own parent umbrella — a cycle, not a real blocker; verify the scaffold landed and check sibling children before treating it as blocking"
metadata:
  node_type: memory
  type: project
  originSessionId: 68b9fac4-9d2a-45aa-b9c7-d8cee0601b33
  modified: 2026-09-06T15:20:15.609Z
---

Child issues in the `gap/presidio` namespace routinely declare
`Blocked by: #<umbrella>` where that umbrella is the **parent that lists the
child among its own acceptance criteria** — a dependency cycle, not a real
blocker. Seen on #486 → #462 (2026-09-06); #462's body says outright "This is an
**umbrella issue**. Child issues are listed under Acceptance Criteria."

`/workflow:next-issue` will try to build a dependency queue and work the umbrella
first. Don't let it. Instead, before deciding:

1. Check whether the scaffold the umbrella tracks actually **landed** (e.g.
   `ls crates/octarine/src/anonymize/`).
2. Check the **sibling children** — if #481-#485, #487 etc. are all CLOSED, they
   all shipped through the same open umbrella, which is the precedent.
3. Then run with `--force-target` and say why.

**Never close the umbrella from a child's PR.** The `Closes #<child>` trailer
closes only the child, which is correct. An umbrella closes when its last child
does — check every child's state before proposing otherwise (on #486 the user
asked to close #462 and the right answer was no: #493, the analyze-side
`ConflictResolution` work, was still open and genuinely unimplemented).

Related: [[project_presidio_audit_issues]], [[feedback_backlog_blocked_by_filter]]
