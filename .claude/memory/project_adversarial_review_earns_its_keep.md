---
name: project-adversarial-review-earns-its-keep
description: The ship-issue review harness found a correctness bug that every deterministic gate passed; run it and re-run it after each fix
metadata:
  node_type: memory
  type: project
  originSessionId: 820f6581-27a7-4556-ad8e-271fd6bd8267
  modified: 2026-09-06T18:20:35.026Z
---

On PR #731 (issue #493, 2026-09-06) the adversarial pre-PR review harness
(`Workflow` + `ship-issue/workflow.js`) found a real correctness bug that
**every** deterministic gate passed over: `just preflight`, clippy `-D warnings`,
arch-check, strict rustdoc, 8514 nextest tests, and 28/28 CI checks.

The bug: containment dedup ordered candidates by confidence and only asked
whether a candidate fell *inside* something already kept — so a high-confidence
inner span sorted first, was kept, and its lower-confidence container was never
tested against it. Both survived, silently violating the documented
"longer wins" contract.

**Re-run the harness after every fix cycle, not just once.** The cycles were not
redundant:

- **Cycle 1** — found the correctness bug.
- **Cycle 2** — confirmed that fix, then caught that the *doc I added in cycle 1*
  overclaimed (promised function-wide validation only one of four strategies
  performs). A fix introducing a new defect is normal, not exceptional.
- **Cycle 3** — clean (`blocking: []`), plus three genuine coverage gaps.

**Why:** deterministic gates check what someone thought to encode. The harness
reasons about whether the code does what its own docs claim — the class of defect
no linter reaches.

**How to apply:** treat `blocking: []` as the only clean signal, and never merge
on CI alone. Two harness gotchas: pass `diff` explicitly or each reviewer derives
its own (losing the single-snapshot guarantee), and args under wrong keys are
silently dropped, yielding a false `clean` from a review that never ran. In a
worktree the plugin path is refused — copy the script in, and delete it before
committing (`.claude/tmp/` is **not** gitignored). See
[[feedback-tests-must-fail-when-inverted]].
