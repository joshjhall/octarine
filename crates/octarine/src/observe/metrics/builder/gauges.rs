//! Gauge extensions for MetricsBuilder
//!
//! Extends MetricsBuilder with gauge-specific methods.
//! NO business logic here - only delegation to implementation.

use super::MetricsBuilder;

/// Extensions for MetricsBuilder related to gauges
impl MetricsBuilder {
    /// Set gauge to specific value
    pub fn gauge(self, value: i64) {
        // Delegate to aggregate function
        super::super::gauge(self.name, value);
    }
}
