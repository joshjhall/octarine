//! Counter extensions for MetricsBuilder
//!
//! Extends MetricsBuilder with counter-specific methods.
//! NO business logic here - only delegation to implementation.

use super::MetricsBuilder;

/// Extensions for MetricsBuilder related to counters
impl MetricsBuilder {
    /// Increment counter by 1
    pub fn increment(self) {
        // Delegate to aggregate function
        super::super::increment(self.name);
    }

    /// Increment counter by specific amount
    pub fn increment_by(self, amount: u64) {
        // Delegate to aggregate function
        super::super::increment_by(self.name, amount);
    }
}
