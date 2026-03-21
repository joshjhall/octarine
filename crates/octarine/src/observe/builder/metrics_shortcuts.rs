//! Shortcut functions for metrics operations
//!
//! Provides convenient functions for tracking metrics.
//! These are scoped to metrics operations only.

use super::ObserveBuilder;

/// Increment counter by 1 (silently fails if metric name is invalid)
pub fn increment(name: impl AsRef<str>) {
    ObserveBuilder::new().metric(name).increment_counter();
}

/// Increment counter by amount (silently fails if metric name is invalid)
pub fn increment_by(name: impl AsRef<str>, amount: u64) {
    ObserveBuilder::new()
        .metric(name)
        .increment_counter_by(amount);
}

/// Set gauge value (silently fails if metric name is invalid)
pub fn gauge(name: impl AsRef<str>, value: i64) {
    ObserveBuilder::new().metric(name).set_gauge(value);
}

/// Record histogram value (silently fails if metric name is invalid)
pub fn record(name: impl AsRef<str>, value: f64) {
    ObserveBuilder::new().metric(name).record_histogram(value);
}
