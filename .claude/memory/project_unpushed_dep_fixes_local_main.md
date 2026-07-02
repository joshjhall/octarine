---
name: project-unpushed-dep-fixes-local-main
description: "When a PR fails security scanners for a dep advisory, check whether the fix already exists as unpushed commits on local main before writing a new dep bump"
metadata:
  node_type: memory
  type: project
  originSessionId: 749363d3-f00f-4bca-a791-04235ec7344d
---

On 2026-07-02, PR #653 failed Cargo Audit / Cargo Deny / OSV Scanner on
`quick-xml` RUSTSEC-2026-0194/0195 (transitive via `phonenumber`). The fix
already existed — but as **unpushed commits on local `main`** (`8e1d44e` bump
quick-xml→0.41, `f66ac0b` AEAD→0.11), never pushed to `origin/main` and in no
PR. `origin/main` itself was still vulnerable, so every open PR was red.

**Why:** `git log origin/main..main` is the diagnostic — local main can carry
committed-but-unpushed dep fixes. A PR branched from `origin/main` won't have
them; neither does CI (which fetches the RustSec DB fresh each run, so a
previously-green main goes red when a new advisory publishes).

**How to apply:** Before writing a new dependency-bump PR to fix a security
advisory, run `git log --oneline origin/main..main` and `git show <sha> --stat`
to check whether the fix is already committed locally. If so, extract those
commits into a `deps/*` branch via `git cherry-pick` (non-destructive — leaves
local main untouched), open a PR, then rebase the blocked feature PR onto that
branch (or onto main after it merges). Watch for [[project_dependabot_coordinated_bumps]]:
the AEAD commit superseded individual Dependabot PRs #650/#651 — comment them as
superseded, close once the coordinated PR merges. See also
[[feedback_pr_auto_merge]].
