//! Singapore NRIC/FIN methods.

use super::*;

impl GovernmentBuilder {
    /// Check if value matches a Singapore NRIC/FIN pattern
    #[must_use]
    pub fn is_singapore_nric(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_singapore_nric(value);
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

    /// Validate Singapore NRIC/FIN format
    pub fn validate_singapore_nric(&self, nric: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_singapore_nric(nric);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "singapore_nric_validation_failed",
                    "Invalid Singapore NRIC format",
                );
            }
        }
        result
    }

    /// Validate Singapore NRIC/FIN with check letter verification
    pub fn validate_singapore_nric_with_checksum(&self, nric: &str) -> Result<(), Problem> {
        self.inner.validate_singapore_nric_with_checksum(nric)
    }
}
