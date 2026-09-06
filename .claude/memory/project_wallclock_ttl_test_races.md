---
name: project_wallclock_ttl_test_races
description: Cache/TTL tests that assert presence right after insert race the scheduler; split presence (long TTL) from expiry (short TTL) rather than widening timeouts
metadata:
  node_type: memory
  type: project
  originSessionId: 26e2bbe8-8788-4a05-a1a0-c933b7b46e79
  modified: 2026-09-06T19:58:12.132Z
---

A test that inserts into a TTL cache and immediately asserts the value is
present is **racing the scheduler**, not testing the cache. `Instant` is
monotonic wall time and does not stop while a thread is descheduled, so a
stall longer than the TTL expires the entry before the first read.

Confirmed in #724 (fixed 2026-09-06, PR #736): `test_cache_expiration`
failed ~1 in 15 runs on the `expired` branch of `get()`, not `absent`.
Reproduced by CPU oversubscription — 0 misses in 500k idle iterations, 1 in
30k at 30x oversubscription with a **68ms** insert→get gap against a 50ms
TTL.

**Why:** presence-after-insert and expiry-within-the-test have
*contradictory* TTL requirements and cannot share one cache. Presence wants
a TTL longer than any plausible stall; expiry wants one short enough to
finish quickly. Widening the timeout hides the mechanism and breaks the
other half.

**How to apply:** split them — presence asserts on a 60s-TTL cache, expiry
keeps the short TTL plus a bounded polling loop and asserts *only* the
expiry direction (monotone-safe: delay can only help it). Prefer asserting
against explicit `Instant` values (`is_expired_at(deadline + 1ms)`) over
sleeping at all. Grep for other `cache_ttl(Duration::from_millis(..))`
tests before assuming this class is gone.

Related: [[feedback_flaky_timing_verify_first]] (reproduce standalone and
read the assertion before calling it a flake — this one was a real bug),
[[feedback_tests_must_fail_when_inverted]].
