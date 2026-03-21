//! Histogram extensions for MetricsBuilder
//!
//! Extends MetricsBuilder with histogram-specific methods.
//! NO business logic here - only delegation to implementation.

use super::MetricsBuilder;

/// Extensions for MetricsBuilder related to histograms
impl MetricsBuilder {
    /// Record value in histogram
    pub fn record(self, value: f64) {
        // Delegate to aggregate function
        super::super::record(self.name, value);
    }
}
