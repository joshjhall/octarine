---
name: feedback-tests-must-fail-when-inverted
description: "Write tests that would fail if the logic inverted, not tests that confirm the happy path — three passed vacuously in one PR"
metadata:
  node_type: memory
  type: feedback
  originSessionId: 820f6581-27a7-4556-ad8e-271fd6bd8267
  modified: 2026-09-06T18:20:22.009Z
---

A test that passes is not evidence the logic is right. Ask of every assertion:
**if I inverted the code under test, would this fail?** If not, the test is
decoration.

Three vacuous tests shipped in a single PR (#731, issue #493), each caught only
by the adversarial review or by deliberately re-checking:

1. **Multibyte boundary test** — every byte offset I picked happened to be a
   valid UTF-8 char boundary, so the snap-to-boundary path never ran. Rewriting
   it against a true mid-character offset exposed a real bug.
2. **Containment tests** — both used *equal* confidence for both matches, so the
   positional tie-break masked an ordering defect where a high-confidence inner
   span survived alongside its low-confidence container.
3. **Equal-span dedup test** — asserted only `out.len() == 1`, never *which*
   copy survived, so the comparator's confidence tie-break was entirely
   unverified; reverting it would have failed nothing.

**Why:** all three passed under `just preflight`, clippy, arch-check, strict
rustdoc, an 8514-test suite, and 28 green CI checks. Green gates say nothing
about whether a test discriminates.

**How to apply:** for each new test, name the mutation it defends against. Pick
inputs that are *hostile* to the implementation (offsets inside multi-byte
chars; the ordering that contradicts the sort key; unequal values where a
tie-break lives). Assert on *which* element survives, not just how many. See
[[project-adversarial-review-earns-its-keep]].
