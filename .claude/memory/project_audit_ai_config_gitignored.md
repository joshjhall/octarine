---
name: audit-ai-config scans a gitignored file
description: audit-ai-config findings against .claude/settings.local.json cannot be fixed via PR because the file is gitignored
type: project
originSessionId: a25812db-9b4f-4430-bd87-4b4f668d9456
---
`audit-ai-config` scans `.claude/settings.local.json`, but that file is
gitignored (`.gitignore:47`) and has never been tracked in the repo.
Findings against it (e.g., issues #188, #75) cannot close through the
normal issue → PR → merge flow.

**Why:** Local permission allowlists are per-developer state; they
diverge across machines and shouldn't be committed. The scanner's
current behavior surfaces real problems, but the fix has to happen
manually in each dev's local file.

**How to apply:** When `/next-issue` picks an issue that only touches
`.claude/settings.local.json`:
1. Apply the fix locally (Edit tool is fine).
2. Validate JSON with `python3 -c 'import json; json.load(...)'`.
3. Close the issue with a comment explaining the local fix — don't
   branch/PR.
4. Consider teaching `audit-ai-config` to skip gitignored files so it
   doesn't repeatedly file un-closable tickets.
