//! Mexico CURP methods.

use super::*;

impl GovernmentBuilder {
    /// Check if value matches a Mexican CURP pattern
    #[must_use]
    pub fn is_mexico_curp(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_mexico_curp(value);
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

    /// Find all Mexican CURPs in text
    #[must_use]
    pub fn find_mexico_curps_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_mexico_curps_in_text(text);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !matches.is_empty() {
                increment_by(metric_names::detected(), matches.len() as u64);
                increment_by(metric_names::government_data_found(), matches.len() as u64);
            }
        }
        matches
    }

    /// Validate Mexican CURP format (without checksum)
    pub fn validate_mexico_curp(&self, curp: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_mexico_curp(curp);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "mexico_curp_validation_failed",
                    "Invalid Mexico CURP format",
                );
            }
        }
        result
    }

    /// Validate Mexican CURP with check digit verification
    pub fn validate_mexico_curp_with_checksum(&self, curp: &str) -> Result<(), Problem> {
        self.inner.validate_mexico_curp_with_checksum(curp)
    }
}
