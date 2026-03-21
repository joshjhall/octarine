//! Generic record extensions for MetricsBuilder
//!
//! Extends MetricsBuilder with methods that work across metric types.
//! NO business logic here - only delegation to implementation.

use super::MetricsBuilder;
use crate::observe::metrics::MetricName;

/// Extensions for MetricsBuilder for generic operations
impl MetricsBuilder {
    /// Get metric name (useful for inspection)
    pub fn name(&self) -> &MetricName {
        &self.name
    }
}
