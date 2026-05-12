//! Thailand TNIN methods.

use super::*;

impl GovernmentBuilder {
    /// Check if value matches a Thai TNIN pattern
    #[must_use]
    pub fn is_thailand_tnin(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_thailand_tnin(value);
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

    /// Find all Thai TNINs in text
    #[must_use]
    pub fn find_thailand_tnins_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_thailand_tnins_in_text(text);
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

    /// Validate Thai TNIN format (without checksum)
    pub fn validate_thailand_tnin(&self, tnin: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_thailand_tnin(tnin);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "thailand_tnin_validation_failed",
                    "Invalid Thailand TNIN format",
                );
            }
        }
        result
    }

    /// Validate Thai TNIN with mod-11 check digit verification
    pub fn validate_thailand_tnin_with_checksum(&self, tnin: &str) -> Result<(), Problem> {
        self.inner.validate_thailand_tnin_with_checksum(tnin)
    }
}
