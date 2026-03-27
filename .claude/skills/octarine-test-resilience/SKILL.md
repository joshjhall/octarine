---
description: Timing-resilient test patterns for octarine. Use when writing tests involving async, timing, sleep, performance benchmarks, or tests that have failed flakily in CI.
---

# Octarine Test Resilience

Tests with timing dependencies are the #1 source of CI flakiness. This skill
prevents writing tests that pass locally but fail under CI coverage
instrumentation (which inflates timing 10-100x).

## Rules

### 1. Never Assert on Absolute Timing

```rust
// WRONG: Hard timing assertion
let start = Instant::now();
do_work();
assert!(start.elapsed() < Duration::from_millis(100));

// CORRECT: Use #[ignore] for perf tests with documented thresholds
#[test]
#[ignore = "perf test - run manually: cargo test test_perf_ -- --ignored"]
fn test_perf_operation_speed() {
    let start = Instant::now();
    for _ in 0..1000 { do_work(); }
    let avg_us = start.elapsed().as_micros() / 1000;
    assert!(avg_us < 50, "Average: {} us (threshold: 50 us)", avg_us);
}
```

### 2. Use Polling Instead of Fixed Sleep

```rust
// WRONG: Fixed sleep hoping work completes
do_async_work();
std::thread::sleep(Duration::from_millis(100));
assert!(work_is_done());

// CORRECT: Poll with timeout
let deadline = Instant::now() + Duration::from_secs(5);
loop {
    if work_is_done() { break; }
    if Instant::now() > deadline {
        panic!("Work did not complete within 5s");
    }
    std::thread::sleep(Duration::from_millis(10));
}
```

### 3. Use Conditional Assertions for State-Dependent Checks

```rust
// WRONG: Assumes specific system state
assert!(!dispatcher_is_degraded());

// CORRECT: Assert only when preconditions hold
let health = dispatcher_health_score();
if health > 0.95 {
    assert!(!dispatcher_is_degraded(),
        "Healthy dispatcher should not be degraded at score {}", health);
}
```

### 4. Small Sleeps Need Justification

If you must sleep in a test, keep it minimal and comment why:

```rust
// Give event queue time to process (nearly instant, but async)
std::thread::sleep(Duration::from_millis(10));
```

Never sleep more than 50ms without a polling alternative.

### 5. Performance Tests Use `#[ignore]`

ALL `test_perf_*` tests MUST be `#[ignore]` with a standard message:

```rust
#[test]
#[ignore = "perf test - run manually: cargo test -p octarine test_perf_ -- --ignored"]
fn test_perf_my_operation() { ... }
```

**Thresholds from docs** (bare metal, no coverage):

| Operation | Threshold |
|-----------|-----------|
| Entropy calculation (short) | <50 us |
| Key strength analysis | <150 us |
| JWT validation | <500 us |
| API key validation | <150 us |
| Credit card Luhn check | <100 us |

### 6. Async Tests: Use Flush, Not Sleep

Use `flush_dispatcher().await` instead of `sleep()` for async event processing.

### 7. Concurrent Tests: Compare Deltas, Not Absolutes

```rust
// WRONG: assert_eq!(get_count("x"), 1);  // Other tests may have incremented
// CORRECT:
let before = get_count("x");
increment("x");
assert_eq!(get_count("x"), before + 1);
```

## When to Use

- Writing any test with `Instant::now()`, `sleep()`, or `Duration`
- Writing async tests with event dispatch or message passing
- Writing performance benchmarks
- Fixing a test that fails intermittently in CI

## When NOT to Use

- Pure unit tests with no timing or async
- Integration tests that hit real services (those have their own patterns)
- `#[ignore]` tests for external dependencies (Docker, APIs)
