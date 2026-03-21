//! Gauges for tracking current values
//!
//! Gauges represent point-in-time measurements that can go up or down.
//! They track the current state of something.
//!
//! # Use Cases
//! - Queue depths
//! - Active connections
//! - Memory usage
//! - Temperature readings
//! - Account balances
//!
//! # Features
//! - Atomic updates (thread-safe)
//! - High/low watermark tracking
//! - Moving averages
//! - Threshold alerts

use parking_lot::RwLock;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Instant;

/// A gauge that tracks current values
#[derive(Clone)]
pub(crate) struct Gauge {
    name: String,
    value: Arc<AtomicI64>,
    watermarks: Arc<RwLock<Watermarks>>,
}

#[derive(Debug, Clone)]
struct Watermarks {
    min: i64,
    max: i64,
    last_updated: Instant,
}

impl Gauge {
    /// Create a new gauge (internal use)
    pub(crate) fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: Arc::new(AtomicI64::new(0)),
            watermarks: Arc::new(RwLock::new(Watermarks {
                min: i64::MAX,
                max: i64::MIN,
                last_updated: Instant::now(),
            })),
        }
    }

    /// Set the gauge to a specific value
    pub(crate) fn set(&self, value: i64) {
        self.value.store(value, Ordering::Relaxed);

        // Update watermarks
        let mut watermarks = self.watermarks.write();
        watermarks.min = watermarks.min.min(value);
        watermarks.max = watermarks.max.max(value);
        watermarks.last_updated = Instant::now();

        // Check thresholds
        super::thresholds::check_threshold(&self.name, value as f64);
    }

    /// Increment the gauge
    pub(crate) fn increment(&self, delta: i64) {
        let old_value = self.value.fetch_add(delta, Ordering::Relaxed);
        let new_value = old_value.saturating_add(delta);

        // Update watermarks
        let mut watermarks = self.watermarks.write();
        watermarks.min = watermarks.min.min(new_value);
        watermarks.max = watermarks.max.max(new_value);
        watermarks.last_updated = Instant::now();
    }

    /// Decrement the gauge
    pub(crate) fn decrement(&self, delta: i64) {
        // Use saturating_neg to avoid overflow on i64::MIN
        self.increment(delta.saturating_neg());
    }

    /// Get the current value
    pub(crate) fn value(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Get a snapshot of the gauge state
    pub(crate) fn snapshot(&self) -> GaugeSnapshot {
        let watermarks = self.watermarks.read();
        GaugeSnapshot {
            name: self.name.clone(),
            value: self.value(),
            min: watermarks.min,
            max: watermarks.max,
            last_updated: watermarks.last_updated,
        }
    }

    /// Reset watermarks (keep current value)
    pub(crate) fn reset_watermarks(&self) {
        let current = self.value();
        let mut watermarks = self.watermarks.write();
        watermarks.min = current;
        watermarks.max = current;
        watermarks.last_updated = Instant::now();
    }
}

/// A point-in-time snapshot of a gauge
#[derive(Debug, Clone)]
pub struct GaugeSnapshot {
    /// Name of the gauge
    pub name: String,
    /// Current gauge value
    pub value: i64,
    /// Minimum value observed
    pub min: i64,
    /// Maximum value observed
    pub max: i64,
    /// When the gauge was last updated
    pub last_updated: Instant,
}

/// Create or get a global gauge by name (internal use)
pub(crate) fn gauge(name: &str) -> Gauge {
    super::global().gauge(name)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_gauge_set() {
        let gauge = Gauge::new("test");
        assert_eq!(gauge.value(), 0);

        gauge.set(42);
        assert_eq!(gauge.value(), 42);

        gauge.set(-10);
        assert_eq!(gauge.value(), -10);
    }

    #[test]
    fn test_gauge_increment_decrement() {
        let gauge = Gauge::new("test");

        gauge.increment(5);
        assert_eq!(gauge.value(), 5);

        gauge.decrement(3);
        assert_eq!(gauge.value(), 2);
    }

    #[test]
    fn test_gauge_watermarks() {
        let gauge = Gauge::new("test");

        gauge.set(10);
        gauge.set(5);
        gauge.set(15);
        gauge.set(3);

        let snapshot = gauge.snapshot();
        assert_eq!(snapshot.min, 3);
        assert_eq!(snapshot.max, 15);
        assert_eq!(snapshot.value, 3);
    }
}
