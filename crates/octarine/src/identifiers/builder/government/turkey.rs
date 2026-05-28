//! Turkey TCKN + license plate methods.

use super::*;

impl GovernmentBuilder {
    /// Check if value matches Turkey TCKN format (bare or labeled)
    #[must_use]
    pub fn is_turkey_tckn(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_turkey_tckn(value);
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

    /// Find all Turkey TCKNs in text (label-anchored)
    #[must_use]
    pub fn find_turkey_tckns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_turkey_tckns_in_text(text);
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

    /// Validate Turkey TCKN format (without checksum)
    pub fn validate_turkey_tckn(&self, tckn: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_turkey_tckn(tckn);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "turkey_tckn_validation_failed",
                    "Invalid Turkey TCKN format",
                );
            }
        }
        result
    }

    /// Validate Turkey TCKN with NVI mod-10 dual-check-digit verification
    pub fn validate_turkey_tckn_with_checksum(&self, tckn: &str) -> Result<(), Problem> {
        self.inner.validate_turkey_tckn_with_checksum(tckn)
    }

    /// Check if value matches Turkey license plate format
    #[must_use]
    pub fn is_turkey_license_plate(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_turkey_license_plate(value);
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

    /// Find all Turkey license plates in text
    #[must_use]
    pub fn find_turkey_license_plates_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_turkey_license_plates_in_text(text);
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

    /// Validate Turkey license plate format
    pub fn validate_turkey_license_plate(&self, plate: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_turkey_license_plate(plate);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "turkey_license_plate_validation_failed",
                    "Invalid Turkey license plate format",
                );
            }
        }
        result
    }
}
