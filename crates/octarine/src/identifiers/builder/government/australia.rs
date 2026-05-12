//! Australia TFN and ABN methods.

use super::*;

impl GovernmentBuilder {
    /// Check if value matches an Australian Tax File Number pattern
    #[must_use]
    pub fn is_australia_tfn(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_australia_tfn(value);
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

    /// Validate Australian TFN format
    pub fn validate_australia_tfn(&self, tfn: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_australia_tfn(tfn);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "australia_tfn_validation_failed",
                    "Invalid Australia TFN format",
                );
            }
        }
        result
    }

    /// Validate Australian TFN with weighted checksum verification
    pub fn validate_australia_tfn_with_checksum(&self, tfn: &str) -> Result<(), Problem> {
        self.inner.validate_australia_tfn_with_checksum(tfn)
    }

    /// Check if value matches an Australian Business Number pattern
    #[must_use]
    pub fn is_australia_abn(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_australia_abn(value);
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

    /// Validate Australian ABN format
    pub fn validate_australia_abn(&self, abn: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_australia_abn(abn);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "australia_abn_validation_failed",
                    "Invalid Australia ABN format",
                );
            }
        }
        result
    }

    /// Validate Australian ABN with weighted checksum verification
    pub fn validate_australia_abn_with_checksum(&self, abn: &str) -> Result<(), Problem> {
        self.inner.validate_australia_abn_with_checksum(abn)
    }
}
