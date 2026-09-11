---
name: project-metrics-tests-global-registry
description: Metric tests asserting exact counter deltas pass under nextest but fail under cargo test / cargo llvm-cov, because the registry is process-global
metadata:
  type: project
---

The observe metrics registry is **process-global**. A test doing
`snapshot() -> act -> snapshot()` and asserting an exact delta
(`assert_eq!(counter, before + 1)`) races every other test recording the same
metric.

This is invisible under `just test`: nextest gives each test its own process.
It fails under `just coverage`, because `cargo llvm-cov` drives `cargo test`,
which shares one process for the whole crate. CI's Coverage job is therefore
the first place it shows up, and the failing set **shifts between runs**.

A per-file `METRICS_LOCK` does not fix it — it serializes one file's tests
against each other, not against the rest of the crate.

**How to assert instead:**

- "this was recorded" → growth (`> before`), or `>= before + payload_len` for
  byte counters (still fails if a count were recorded in place of a byte total).
- "silent() records nothing" / "a failure doesn't count" → assert at the
  **gate** (the `emit_events` / `metrics_enabled` flag every `record()` and
  `increment_by()` sits behind), not by watching a global counter. Always also
  assert the default differs, or the test passes vacuously — see
  [[feedback_tests_must_fail_when_inverted]].
- Genuinely need serialization? `observe::metrics::metrics_test_lock()` is a
  crate-wide lock (added in #417).

The same shape bites non-metric global state: `identifiers/builder/government/cache`
had two tests racing on the process-global validation cache (one clears what
the other reads), fixed with a file-local mutex in the same PR.

**Before pushing metrics work, run `cargo test --workspace --all-features`
several times**, not just `just test` — one clean run proves nothing here.
