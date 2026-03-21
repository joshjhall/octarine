//! Metrics extensions for ObserveBuilder
//!
//! Provides metrics methods that delegate to MetricsBuilder internally.

use super::ObserveBuilder;
use crate::observe::metrics::MetricsBuilder;

/// Extensions for ObserveBuilder related to metrics
impl ObserveBuilder {
    /// Increment counter by 1
    pub fn increment_counter(self) {
        if let Some(name) = self.metric_name {
            MetricsBuilder::new(name).increment();
        }
    }

    /// Increment counter by amount
    pub fn increment_counter_by(self, amount: u64) {
        if let Some(name) = self.metric_name {
            MetricsBuilder::new(name).increment_by(amount);
        }
    }

    /// Set gauge value
    pub fn set_gauge(self, value: i64) {
        if let Some(name) = self.metric_name {
            MetricsBuilder::new(name).gauge(value);
        }
    }

    /// Record histogram value
    pub fn record_histogram(self, value: f64) {
        if let Some(name) = self.metric_name {
            MetricsBuilder::new(name).record(value);
        }
    }
}
