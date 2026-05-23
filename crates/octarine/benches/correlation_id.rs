//! Performance benchmarks for correlation ID lookup paths
//!
//! Documents the four code paths through `primitives::runtime::correlation_id()`:
//!
//! - `cold_fallback` — `clear_correlation_id()` + `correlation_id()` per
//!   iteration. Forces UUID generation every call (worst case).
//! - `cached_fallback` — single `clear_correlation_id()` outside the loop,
//!   then `correlation_id()` in the loop. After the seeding change this
//!   should match `thread_local_hit` (both are thread-local reads).
//! - `thread_local_hit` — explicit `set_correlation_id()`, then loop. The
//!   classic sync-with-context fast path.
//! - `task_local_hit` — inside a `with_correlation_id()` async scope. The
//!   classic async fast path.
//!
//! Run with: `cargo bench --bench correlation_id`

#![allow(clippy::panic, clippy::expect_used, clippy::print_stdout, missing_docs)]

use criterion::{Criterion, criterion_group, criterion_main};
use octarine::runtime::r#async::{
    clear_correlation_id, correlation_id, set_correlation_id, with_correlation_id,
};
use std::hint::black_box;
use tokio::runtime::Runtime;
use uuid::Uuid;

fn bench_cold_fallback(c: &mut Criterion) {
    c.bench_function("correlation_id/cold_fallback", |b| {
        b.iter(|| {
            // Clear before every call forces the fallback to generate a UUID.
            clear_correlation_id();
            black_box(correlation_id())
        });
    });
    clear_correlation_id();
}

fn bench_cached_fallback(c: &mut Criterion) {
    c.bench_function("correlation_id/cached_fallback", |b| {
        // Seed once via the fallback path; subsequent calls hit thread-local.
        clear_correlation_id();
        let _ = correlation_id();
        b.iter(|| black_box(correlation_id()));
    });
    clear_correlation_id();
}

fn bench_thread_local_hit(c: &mut Criterion) {
    c.bench_function("correlation_id/thread_local_hit", |b| {
        set_correlation_id(Uuid::new_v4());
        b.iter(|| black_box(correlation_id()));
    });
    clear_correlation_id();
}

fn bench_task_local_hit(c: &mut Criterion) {
    // task_local requires a tokio runtime
    let rt = Runtime::new().expect("failed to build tokio runtime");
    c.bench_function("correlation_id/task_local_hit", |b| {
        let id = Uuid::new_v4();
        b.iter(|| {
            rt.block_on(with_correlation_id(id, async {
                black_box(correlation_id())
            }))
        });
    });
}

criterion_group!(
    benches,
    bench_cold_fallback,
    bench_cached_fallback,
    bench_thread_local_hit,
    bench_task_local_hit,
);
criterion_main!(benches);
