---
name: project_metrics_thread_local_tally
description: For "this metric was NOT recorded" assertions use the thread-local tally, not the global registry snapshot — metrics_test_lock() cannot make a zero-delta safe
metadata:
  type: project
---

To assert a metric was **not** recorded, use
`observe::metrics::{local_metric_count, reset_local_metrics}` (added #793,
merged in #795) — never a `snapshot()` delta.

`metrics_test_lock()` does NOT make an absolute `delta == 0` safe. The lock is
**opt-in**: it serializes only the handful of tests that take it, while
`ConfigBuilder::new()` alone appears at ~60 call sites that don't. Several tests
carried a comment claiming "both measurements sit inside ONE lock hold, so
concurrent siblings cannot skew the comparison" — that reasoning was wrong, and
was the cause of the red `Coverage` job on unrelated PRs.

The tally is a thread-local incremented at the `queue_*` entry points, which run
synchronously on the calling thread. Each test owns its thread, so the count is
exact, needs no `flush_for_testing()`, and is *stronger* than the growth
assertion in [[project_metrics_tests_global_registry]] — use growth only when
the global registry is genuinely what's under test.

Two limits: it covers the `increment*`/`gauge`/`record` path only (a
`MetricTimer` writes to the registry directly on drop), and it assumes the
recording happens on the thread that called `reset_local_metrics()` — so it is
wrong under `#[tokio::test(flavor = "multi_thread")]` or when a builder records
from a spawned task. Hardening tracked in #798.

**Why:** an unsound zero-delta assertion is invisible — it passes under nextest
(process-per-test) and fails only under `cargo test`/coverage.

**How to apply:** reach for the tally for any "silent() must not record"
assertion; see [[feedback_tests_must_fail_when_inverted]] — verify by deleting
the `if emit_events` guard and confirming the test fails.
