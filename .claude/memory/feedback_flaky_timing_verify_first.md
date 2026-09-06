---
name: feedback_flaky_timing_verify_first
description: "Don't write off an intermittent timing test as flake — reproduce it in isolation and read the assertion before judging"
metadata:
  node_type: memory
  type: feedback
  originSessionId: 8344eb3e-0ff4-49dc-b7a4-3ccee64b1fd1
  modified: 2026-09-05T23:11:56.258Z
---

An intermittently failing timing test is **not** flake until proven so. Two
checks, both cheap, before applying the label:

1. **Reproduce in isolation on an idle machine.** Load-induced flake needs
   load. If it fails standalone, it is a bug.
2. **Read the assertion message.** Not the test name, not the duration —
   the `left`/`right` values and the panicking line number.

Skipping these produced two wrong calls in one session (2026-09-05):

- `auth::timing::tests::test_constant_time_response_async_fast` was written
  off as parallel-load flake across two separate occasions. It reproduced
  **5 of 8 runs standalone**, with `left: 49ms, right: 50ms`. Real bug:
  `constant_time_response` measured with `std::time::Instant` but padded
  with `tokio::time::sleep`, so under `tokio::time::pause()` real elapsed
  time was subtracted from a virtual sleep, under-padding a security floor
  (fixed in #723 / PR #726). What varied was machine speed, not
  contention — which is exactly why it *looked* environmental.
- `test_cache_expiration` was called a "polling timeout" from its 16.8s
  duration alone. The message said otherwise: `left: None, right:
  Some("value")` at the assertion *before* the wait — the entry is missing
  microseconds after insert (filed as #724).

**Why:** these tests were correct and were reporting genuine defects. The
"flaky" label ends investigation, so a wrong one buries a real bug —
here, one that silently weakened a timing-attack defense.

**How to apply:** when tempted to say "pre-existing flake", first run it
standalone in a loop (`for i in $(seq 1 15)`) and capture the panic with
`--nocapture`. Say "environmental" only with evidence — e.g. a checked
`/proc/loadavg` and swap figure. Prefer targeted builds
(`cargo test -p octarine-core --lib --features auth <filter>`) over
`--all-features` workspace runs when iterating; the latter OOM-killed this
box repeatedly and *created* the load being blamed.

Clock-domain rule this uncovered: measure on the same clock you sleep on —
`tokio::time::Instant` with `tokio::time::sleep`, `std::time::Instant` with
`std::thread::sleep`. See [[octarine-test-resilience]] for the timing-test
rules and [[project_flaky_cache_cleanup_test]] for a genuine flake fix.
