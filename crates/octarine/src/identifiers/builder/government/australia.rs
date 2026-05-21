//! Australia TFN, ABN, Medicare, and ACN methods.

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

    /// Find all Australian TFNs in text
    #[must_use]
    pub fn find_australia_tfns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_australia_tfns_in_text(text);
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

    /// Find all Australian ABNs in text
    #[must_use]
    pub fn find_australia_abns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_australia_abns_in_text(text);
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

    /// Check if value matches an Australian Medicare pattern
    #[must_use]
    pub fn is_australia_medicare(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_australia_medicare(value);
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

    /// Find all Australian Medicare numbers in text
    #[must_use]
    pub fn find_australia_medicares_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_australia_medicares_in_text(text);
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

    /// Validate Australian Medicare format
    pub fn validate_australia_medicare(&self, value: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_australia_medicare(value);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "australia_medicare_validation_failed",
                    "Invalid Australia Medicare format",
                );
            }
        }
        result
    }

    /// Validate Australian Medicare with weighted mod-10 checksum
    pub fn validate_australia_medicare_with_checksum(&self, value: &str) -> Result<(), Problem> {
        self.inner.validate_australia_medicare_with_checksum(value)
    }

    /// Check if value matches an Australian Company Number pattern
    #[must_use]
    pub fn is_australia_acn(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_australia_acn(value);
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

    /// Find all Australian ACNs in text
    #[must_use]
    pub fn find_australia_acns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_australia_acns_in_text(text);
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

    /// Validate Australian ACN format
    pub fn validate_australia_acn(&self, acn: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_australia_acn(acn);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "australia_acn_validation_failed",
                    "Invalid Australia ACN format",
                );
            }
        }
        result
    }

    /// Validate Australian ACN with weighted mod-10 checksum
    pub fn validate_australia_acn_with_checksum(&self, acn: &str) -> Result<(), Problem> {
        self.inner.validate_australia_acn_with_checksum(acn)
    }
}
