//! South Korea RRN methods.

use super::*;

impl GovernmentBuilder {
    /// Check if value matches a South Korean RRN pattern
    #[must_use]
    pub fn is_korea_rrn(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_korea_rrn(value);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result {
                increment_by(metric_names::detected(), 1);
                increment_by(metric_names::government_data_found(), 1);
            }
        }
        result
    }

    /// Validate South Korean RRN format
    pub fn validate_korea_rrn(&self, rrn: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_korea_rrn(rrn);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn("korea_rrn_validation_failed", "Invalid Korea RRN format");
            }
        }
        result
    }

    /// Validate South Korean RRN with weighted checksum verification
    pub fn validate_korea_rrn_with_checksum(&self, rrn: &str) -> Result<(), Problem> {
        self.inner.validate_korea_rrn_with_checksum(rrn)
    }
}
