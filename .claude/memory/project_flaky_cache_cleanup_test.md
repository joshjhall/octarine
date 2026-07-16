---
name: project_flaky_cache_cleanup_test
description: test_cache_cleanup in collections/cache/lru.rs WAS timing-flaky under parallel load; fixed 2026-07-16
metadata:
  node_type: memory
  type: project
  originSessionId: 048717ce-bb41-48f6-9632-cc44f81b712c
---

`primitives::collections::cache::lru::tests::test_cache_cleanup`
(`crates/octarine/src/primitives/collections/cache/lru.rs`) used to flake under
full-parallel load (`just test`, `just release` preflight — no retries there)
with "Timed out waiting for 5 entries to expire (got 0, len 0)", while passing in
isolation.

**Root cause (now understood):** the 5 entries are inserted at slightly different
instants, so under load they expire *piecemeal* across several `cleanup_expired()`
calls (one removes 3, the next 2). The test demanded a **single** call return
exactly 5, which never happened — the cache drained to empty without any one call
seeing 5. Not a timing-threshold problem; a single-call-vs-accumulate race.

**Fix (2026-07-16):** accumulate the removed count across poll iterations
(`expired += cache.cleanup_expired()` until `>= 5`) instead of requiring one call
to return 5 — `octarine-test-resilience` Rule 6 (measure the total delta).
Verified 10× in isolation + full-workspace `cargo nextest` (8477/8477) under the
same contention that failed the release. Shipped on branch
`fix/flaky-cache-cleanup-test`.

**How to apply:** this specific flake should no longer recur. If it does, the
`cleanup_expired` accumulation loop is the place to look. Related:
[[project_ci_macos_cache_poisoning]].
