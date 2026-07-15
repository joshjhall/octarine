---
name: project_flaky_cache_cleanup_test
description: test_cache_cleanup in collections/cache/lru.rs is timing-flaky under parallel load
metadata:
  node_type: memory
  type: project
  originSessionId: 048717ce-bb41-48f6-9632-cc44f81b712c
---

`primitives::collections::cache::lru::tests::test_cache_cleanup`
(`crates/octarine/src/primitives/collections/cache/lru.rs:416`) is a
timing-based expiry test that flakes under `just test` when the runner is
under load (e.g. after fd exhaustion / heavy parallel linking) — fails with
"Timed out waiting for 5 entries to expire (got 0, len 0)". It passes reliably
in isolation (`just test-filter test_cache_cleanup`).

**Why:** hard timing assertion on TTL expiry, the exact anti-pattern
`octarine-test-resilience` warns about.

**How to apply:** if a `/next-issue` full-suite run fails ONLY on this test,
confirm it passes in isolation and treat it as pre-existing flake, not a
regression from your change. Candidate for a poll-with-timeout fix under its
own issue. Related: [[project_ci_macos_cache_poisoning]].
