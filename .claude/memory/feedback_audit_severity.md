---
name: Audit severity and deduplication preference
description: When running codebase audits, file all findings (including low severity) but deduplicate aggressively against existing issues
type: feedback
originSessionId: 4463311d-805b-4c18-b59e-4729660c355c
---
When running `/codebase-audit`, default to `severity-threshold=low` (file everything) but ensure each filed issue is clearly defined and deduplicated against existing open issues.

**Why:** User closed 100+ issues in the 3-4 weeks before 2026-04-16, so backlog flooding is not a concern — quality and dedup are. Duplicate issues create noise; missed findings create hidden debt. The plan is to run audits iteratively: file everything → work through for 1-2 weeks → run another audit pass → repeat.

**How to apply:** When invoking audit flow (or recommending params), pass `severity-threshold=low` and `dry-run=false`. Emphasize dedup in issue-writer dispatch. For multi-pass cleanup cycles, suggest re-running audit every 1-2 weeks after issues are worked down.
