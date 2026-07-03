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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Checksum-valid samples (verified in the primitive validation tests):
    //   TFN "123 456 782" (weighted mod-11)
    //   ABN "51 824 753 556" (mod-89)
    //   Medicare "2123456701" (weighted mod-10)
    //   ACN "004 085 616" (weighted mod-10)
    const VALID_TFN: &str = "123 456 782";
    const VALID_ABN: &str = "51 824 753 556";
    // Detection requires the spaced/labeled form; validators accept the
    // compact 10-digit form too.
    const VALID_MEDICARE: &str = "2123 45670 1";
    const VALID_MEDICARE_COMPACT: &str = "2123456701";
    const VALID_ACN: &str = "004 085 616";

    #[test]
    fn test_tfn() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_australia_tfn(VALID_TFN));
        assert!(!b.is_australia_tfn("12"));
        assert!(b.validate_australia_tfn(VALID_TFN).is_ok());
        // 7 digits — wrong length.
        assert!(b.validate_australia_tfn("1234567").is_err());
        assert!(b.validate_australia_tfn_with_checksum(VALID_TFN).is_ok());
        // Break checksum (last digit 2 -> 3).
        assert!(
            b.validate_australia_tfn_with_checksum("123 456 783")
                .is_err()
        );
        assert!(!b.find_australia_tfns_in_text("TFN 123 456 782").is_empty());
    }

    #[test]
    fn test_tfn_events_enabled() {
        let b = GovernmentBuilder::new();
        assert!(b.is_australia_tfn(VALID_TFN));
        assert!(b.validate_australia_tfn(VALID_TFN).is_ok());
    }

    #[test]
    fn test_abn() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_australia_abn(VALID_ABN));
        assert!(b.validate_australia_abn(VALID_ABN).is_ok());
        // 10 digits — wrong length.
        assert!(b.validate_australia_abn("1234567890").is_err());
        assert!(b.validate_australia_abn_with_checksum(VALID_ABN).is_ok());
        // Break checksum.
        assert!(
            b.validate_australia_abn_with_checksum("51 824 753 557")
                .is_err()
        );
        assert!(
            !b.find_australia_abns_in_text("ABN 51 824 753 556")
                .is_empty()
        );
    }

    #[test]
    fn test_medicare() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_australia_medicare(VALID_MEDICARE));
        assert!(
            b.validate_australia_medicare(VALID_MEDICARE_COMPACT)
                .is_ok()
        );
        // First digit must be 2-6; 1 is invalid.
        assert!(b.validate_australia_medicare("1123456701").is_err());
        assert!(
            b.validate_australia_medicare_with_checksum(VALID_MEDICARE_COMPACT)
                .is_ok()
        );
        // Break checksum (check digit 0 -> 1).
        assert!(
            b.validate_australia_medicare_with_checksum("2123456711")
                .is_err()
        );
        assert!(
            !b.find_australia_medicares_in_text("Medicare 2123 45670 1")
                .is_empty()
        );
    }

    #[test]
    fn test_acn() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_australia_acn(VALID_ACN));
        assert!(b.validate_australia_acn(VALID_ACN).is_ok());
        // 8 digits — wrong length.
        assert!(b.validate_australia_acn("12345678").is_err());
        assert!(b.validate_australia_acn_with_checksum(VALID_ACN).is_ok());
        // Break checksum (last digit 6 -> 7).
        assert!(
            b.validate_australia_acn_with_checksum("004 085 617")
                .is_err()
        );
        assert!(!b.find_australia_acns_in_text("ACN 004 085 616").is_empty());
    }
}
