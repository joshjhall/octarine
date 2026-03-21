//! Counters for tracking event frequencies
//!
//! Counters are monotonically increasing values that track how often
//! things happen. They can only increment, never decrement.
//!
//! # Use Cases
//! - Request counts
//! - Error counts
//! - Event occurrences
//! - Operation completions
//!
//! # Features
//! - Atomic increments (thread-safe)
//! - Rate calculations (events/second)
//! - Automatic context enrichment
//! - Threshold alerts

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// A monotonically increasing counter
#[derive(Clone)]
pub(crate) struct Counter {
    name: String,
    value: Arc<AtomicU64>,
    created_at: Instant,
}

impl Counter {
    /// Create a new counter (internal use)
    pub(crate) fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: Arc::new(AtomicU64::new(0)),
            created_at: Instant::now(),
        }
    }

    /// Increment the counter by 1
    pub(crate) fn increment(&self) {
        let new_value = self.value.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        super::thresholds::check_threshold(&self.name, new_value as f64);
    }

    /// Increment the counter by a specific amount
    pub(crate) fn increment_by(&self, amount: u64) {
        let new_value = self
            .value
            .fetch_add(amount, Ordering::Relaxed)
            .saturating_add(amount);
        super::thresholds::check_threshold(&self.name, new_value as f64);
    }

    /// Get the current value
    pub(crate) fn value(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Get the rate per second since creation
    pub(crate) fn rate_per_second(&self) -> f64 {
        let elapsed = self.created_at.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.value() as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Reset the counter to zero (useful for interval-based metrics)
    pub(crate) fn reset(&self) -> u64 {
        self.value.swap(0, Ordering::Relaxed)
    }

    /// Get a snapshot of the counter state
    pub(crate) fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            name: self.name.clone(),
            value: self.value(),
            rate_per_second: self.rate_per_second(),
            created_at: self.created_at,
        }
    }
}

/// A point-in-time snapshot of a counter
#[derive(Debug, Clone)]
pub struct CounterSnapshot {
    /// Name of the counter
    pub name: String,
    /// Current counter value
    pub value: u64,
    /// Rate of change per second
    pub rate_per_second: f64,
    /// When the counter was created
    pub created_at: Instant,
}

/// Create or get a global counter by name (internal use)
pub(crate) fn counter(name: &str) -> Counter {
    super::global().counter(name)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_counter_increment() {
        let counter = Counter::new("test");
        assert_eq!(counter.value(), 0);

        counter.increment();
        assert_eq!(counter.value(), 1);

        counter.increment_by(5);
        assert_eq!(counter.value(), 6);
    }

    #[test]
    fn test_counter_reset() {
        let counter = Counter::new("test");
        counter.increment_by(10);

        let old_value = counter.reset();
        assert_eq!(old_value, 10);
        assert_eq!(counter.value(), 0);
    }
}
