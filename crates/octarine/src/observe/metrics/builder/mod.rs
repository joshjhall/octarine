//! Metrics builder for configurable metric operations
//!
//! Provides a builder pattern for working with metrics.
//! This follows the three-layer pattern where the builder orchestrates
//! but doesn't implement business logic - it delegates to domain functions.

use super::MetricName;

// Extension modules that add methods to MetricsBuilder
mod counters;
mod gauges;
mod histograms;
mod record;

/// Main metrics builder for configurable metric operations
#[derive(Debug, Clone)]
pub(in crate::observe) struct MetricsBuilder {
    /// Metric name (validated at construction)
    pub(super) name: MetricName,
}

impl MetricsBuilder {
    /// Create a new metrics builder with a validated metric name
    ///
    /// This is type-safe - validation happens when creating the MetricName.
    pub fn new(name: MetricName) -> Self {
        Self { name }
    }
}

impl Default for MetricsBuilder {
    fn default() -> Self {
        // Use a valid default name
        Self {
            name: MetricName::from_static_str("default.metric"),
        }
    }
}
