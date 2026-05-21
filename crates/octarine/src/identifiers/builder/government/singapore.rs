//! Singapore NRIC/FIN and UEN methods.

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

    /// Find all Singapore NRIC/FIN numbers in text
    #[must_use]
    pub fn find_singapore_nrics_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_singapore_nrics_in_text(text);
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

    /// Check if value matches a Singapore UEN layout
    #[must_use]
    pub fn is_singapore_uen(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_singapore_uen(value);
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

    /// Find all Singapore UEN values in text
    #[must_use]
    pub fn find_singapore_uens_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_singapore_uens_in_text(text);
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

    /// Validate Singapore UEN layout
    pub fn validate_singapore_uen(&self, uen: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_singapore_uen(uen);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "singapore_uen_validation_failed",
                    "Invalid Singapore UEN layout",
                );
            }
        }
        result
    }
}
