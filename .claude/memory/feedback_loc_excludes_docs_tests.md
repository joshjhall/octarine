---
name: LOC counts exclude docs and tests
description: When evaluating file size against octarine size limits (preferred <300, warn >500, split >800), count only production code — exclude doc comments and #[cfg(test)] modules
type: feedback
originSessionId: 8b312243-2a09-4133-8ff4-148b83dddacb
---
When checking whether a file exceeds octarine's size limits documented in CLAUDE.md (preferred <300 LOC, warn >500, split at >800), the LOC measurement is **production code only**. Exclude:

- Doc comments (`///`, `//!`, `/** */`)
- `#[cfg(test)] mod tests { ... }` blocks
- Module-level `//!` headers

**Why:** A 2014-line file with ~1000 lines of tests and ~200 lines of doc comments is really ~800 lines of production code. The size guidance targets the cognitive load of reviewable production logic, not test coverage or documentation thoroughness. Tests are a feature, not debt — splitting a file just because tests pushed it over the line is wrong.

**How to apply:**
- Before flagging or planning a split, compute production LOC: `wc -l file.rs` minus the test module line count minus large doc comment blocks.
- When sizing target submodules in a split plan, target <300 LOC of production code per file (tests bundled with the production code don't count against that target).
- When reporting "this file is X LOC" in plans/PRs, qualify with "(of which N is tests, M is docs)" if tests/docs are a significant fraction.
- Audit findings flagging "X-line god module" should still be addressed if the production logic itself is large or has high fan-in — but use the production LOC, not raw line count, as the threshold.
