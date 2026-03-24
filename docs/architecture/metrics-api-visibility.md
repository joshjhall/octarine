# Metrics API Visibility Analysis

## Current State Analysis

### Public API Surface (What's Currently Exposed)

1. **Top-level module exports** (`src/observe/metrics/mod.rs`):

   - All submodules are `pub mod` (counters, gauges, histograms, timers, aggregation)
   - Types: Counter, Gauge, Histogram, Timer, Snapshots
   - Functions: counter(), gauge(), histogram(), timer()
   - Global functions: increment(), gauge_value(), record()

1. **Counter module** (`counters/mod.rs`):

   - `Counter::new()` - Should be pub(crate) or private
   - All Counter methods are public
   - `counter()` function duplicates parent module

1. **Issues Identified**:

   - Too much internal implementation exposed
   - Duplicate convenience functions at multiple levels
   - Direct construction allowed when registry should be used

## Proposed Visibility Strategy

### Design Principles

1. **Single Entry Point**: Users should primarily interact through the registry
1. **Hide Implementation**: Internal types should be pub(crate) at most
1. **Minimal Surface**: Only expose what's needed for the API
1. **Builder Pattern**: Complex configurations through builders, not direct construction

### Recommended API Structure

```rust
// PUBLIC API (from observe::metrics)
pub use self::types::{
    CounterSnapshot,
    GaugeSnapshot,
    HistogramSnapshot,
    MetricsSnapshot,
};

// Convenience functions (the primary API)
pub fn increment(name: &str);
pub fn increment_by(name: &str, value: u64);
pub fn gauge(name: &str, value: i64);
pub fn record(name: &str, value: f64);
pub fn timer(name: &str) -> Timer;
pub fn time_fn<F, R>(name: &str, f: F) -> R;

// Advanced usage (secondary API)
pub fn with_registry<R>(registry: &Registry, f: impl FnOnce() -> R) -> R;
pub fn snapshot() -> MetricsSnapshot;

// INTERNAL (pub(crate) or private)
pub(crate) struct Counter { ... }
pub(crate) struct Gauge { ... }
pub(crate) struct Histogram { ... }
pub(crate) struct Registry { ... }
```

### Module Visibility Changes

```rust
// src/observe/metrics/mod.rs
mod counters;      // Private - implementation detail
mod gauges;        // Private - implementation detail
mod histograms;    // Private - implementation detail
mod timers;        // Private - implementation detail
pub(crate) mod aggregation; // Internal for observe module

// Only export what users need
pub use timers::Timer; // Must be public for RAII pattern
```

### Method Visibility per Type

#### Counter (internal type)

```rust
impl Counter {
    pub(crate) fn new() -> Self              // Only for registry
    pub(crate) fn increment(&self)           // Used by registry
    pub(crate) fn increment_by(&self, u64)   // Used by registry
    pub(crate) fn value(&self) -> u64        // For snapshots
    pub(crate) fn snapshot(&self) -> Snapshot // For exports

    // These could be private:
    fn rate_per_second(&self) -> f64         // Only for snapshots
    fn reset(&self) -> u64                   // Rarely needed
}
```

#### Timer (public type due to RAII)

```rust
pub struct Timer { ... }

impl Timer {
    pub(crate) fn new() -> Self    // Only created via timer()
    pub fn cancel(self)             // User needs this
    pub fn elapsed(&self) -> Duration // User might need this
    // record() handled by Drop
}
```

## Implementation Plan

### Phase 1: Reduce Module Visibility

1. Change submodules from `pub mod` to `mod` (except where needed)
1. Add pub(crate) to types that observe internals need
1. Remove duplicate convenience functions

### Phase 2: Refine Type Visibility

1. Make Counter, Gauge, Histogram pub(crate)
1. Keep only Timer public (for RAII)
1. Make Registry pub(crate)

### Phase 3: Method Visibility

1. Review each public method
1. Change to pub(crate) if only used internally
1. Make private if only used within module

### Phase 4: Add Builder API (Future)

```rust
pub fn configure() -> MetricsBuilder {
    MetricsBuilder::new()
}

impl MetricsBuilder {
    pub fn with_registry(self, registry: Registry) -> Self
    pub fn with_context(self, ctx: Context) -> Self
    pub fn build(self) -> MetricsHandle
}
```

## Benefits of This Approach

1. **Cleaner API**: Users see only what they need
1. **Future Flexibility**: Can change internals without breaking changes
1. **Better Encapsulation**: Implementation details hidden
1. **Single Source of Truth**: Registry manages all metrics
1. **Consistent Access Pattern**: Always go through convenience functions

## Migration Path

Since this is still internal (0.1.0), we can make these changes now:

1. Start with the most restrictive visibility
1. Only expose what's actively used
1. Add pub incrementally as needed
1. Document the public API clearly
