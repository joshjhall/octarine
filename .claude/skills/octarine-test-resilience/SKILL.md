---
description: Timing-resilient test patterns for octarine. Use when writing tests involving async, timing, Instant, Duration, sleep, performance benchmarks, or tests that have failed flakily in CI.
---

# Octarine Test Resilience

CI coverage instrumentation inflates timing 10-100x. These rules prevent
flaky test failures.

## Resilience Rules

### Rule 1: Never Assert on Absolute Timing

CI timing is unreliable. Use `#[ignore]` for any test asserting elapsed time:

```rust
// WRONG: Will fail under CI coverage
assert!(elapsed < Duration::from_millis(100));

// CORRECT: Mark as perf test
#[ignore = "perf test - run manually with: cargo test -p octarine test_perf_ -- --ignored"]
fn test_perf_operation_speed() { ... }
```

**Exception**: Tests comparing RELATIVE timing (A faster than B) are OK
without `#[ignore]`.

### Rule 2: Use Polling With Timeout, Not Fixed Sleep

```rust
// WRONG: Fixed sleep, fails if system is slow
thread::sleep(Duration::from_millis(200));
assert!(result.is_ready());

// CORRECT: Poll with timeout
let deadline = Instant::now() + Duration::from_secs(5);
loop {
    if result.is_ready() { break; }
    if Instant::now() > deadline { panic!("Timed out waiting for result"); }
    thread::sleep(Duration::from_millis(10));
}
```

Note: `panic!()` is allowed in test modules with `#![allow(clippy::panic)]`.

### Rule 3: Conditional Assertions for State-Dependent Checks

Assert only when preconditions hold — skip timing-dependent assertions when
system state is unknown (e.g., check `health_score > 0.95` before asserting
dispatch behavior).

### Rule 4: Small Sleeps Need Justification

Sleeps <=50ms are acceptable with a comment explaining why. Sleeps >50ms
must use polling (Rule 2).

### Rule 5: Performance Tests Use `#[ignore]`

ALL `test_perf_*` functions MUST have `#[ignore]`. Run them manually:

```bash
just test-perf
```

Performance thresholds are documented in `docs/architecture/testing-patterns.md`
— reference that file for current per-operation values.

### Rule 6: Compare Deltas, Not Absolutes

In concurrent tests, measure change rather than absolute state:

```rust
// WRONG: Other tests may have incremented the counter
assert_eq!(get_count("metric"), 1);

// CORRECT: Measure the delta
let before = get_count("metric");
do_operation();
assert_eq!(get_count("metric"), before + 1);
```

## When to Use

- Writing tests with `Instant::now()`, `sleep()`, `Duration`
- Writing async tests with event dispatch
- Writing performance benchmarks
- Fixing intermittent CI failures

## When NOT to Use

- Unit tests with no timing or async concerns
- Integration tests hitting real services (see `docs/architecture/testing-patterns.md`)
- Production code timing (different concern)
