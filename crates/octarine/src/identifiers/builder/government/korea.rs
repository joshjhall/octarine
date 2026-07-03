//! South Korea identifier methods (RRN, FRN, Driver License, Passport, BRN).

use super::*;

impl GovernmentBuilder {
    // =========================================================================
    // RRN — Resident Registration Number (citizens, gender digit 1-4)
    // =========================================================================

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

    /// Find all South Korean RRNs in text
    #[must_use]
    pub fn find_korea_rrns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_korea_rrns_in_text(text);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !matches.is_empty() {
                increment_by(metric_names::detected(), matches.len() as u64);
            }
        }
        matches
    }

    /// Validate South Korean RRN format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the RRN format is invalid
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
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the RRN format is invalid or checksum fails
    pub fn validate_korea_rrn_with_checksum(&self, rrn: &str) -> Result<(), Problem> {
        self.inner.validate_korea_rrn_with_checksum(rrn)
    }

    // =========================================================================
    // FRN — Foreign Registration Number (foreigners, gender digit 5-8)
    // =========================================================================

    /// Check if value matches a South Korean FRN pattern
    #[must_use]
    pub fn is_korea_frn(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_korea_frn(value);
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

    /// Find all South Korean FRNs in text
    #[must_use]
    pub fn find_korea_frns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_korea_frns_in_text(text);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !matches.is_empty() {
                increment_by(metric_names::detected(), matches.len() as u64);
            }
        }
        matches
    }

    /// Validate South Korean FRN format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the FRN format is invalid
    pub fn validate_korea_frn(&self, frn: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_korea_frn(frn);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn("korea_frn_validation_failed", "Invalid Korea FRN format");
            }
        }
        result
    }

    /// Validate South Korean FRN with weighted checksum verification
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the FRN format is invalid or checksum fails
    pub fn validate_korea_frn_with_checksum(&self, frn: &str) -> Result<(), Problem> {
        self.inner.validate_korea_frn_with_checksum(frn)
    }

    // =========================================================================
    // Driver License
    // =========================================================================

    /// Check if value matches a South Korean Driver License pattern
    #[must_use]
    pub fn is_korea_driver_license(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_korea_driver_license(value);
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

    /// Find all South Korean Driver Licenses in text
    #[must_use]
    pub fn find_korea_driver_licenses_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_korea_driver_licenses_in_text(text);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !matches.is_empty() {
                increment_by(metric_names::detected(), matches.len() as u64);
            }
        }
        matches
    }

    /// Validate South Korean Driver License format and region
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the license format or region is invalid
    pub fn validate_korea_driver_license(&self, dl: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_korea_driver_license(dl);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "korea_driver_license_validation_failed",
                    "Invalid Korea Driver License format",
                );
            }
        }
        result
    }

    // =========================================================================
    // Passport
    // =========================================================================

    /// Check if value matches a South Korean Passport pattern
    #[must_use]
    pub fn is_korea_passport(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_korea_passport(value);
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

    /// Find all South Korean passports in text
    #[must_use]
    pub fn find_korea_passports_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_korea_passports_in_text(text);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !matches.is_empty() {
                increment_by(metric_names::detected(), matches.len() as u64);
            }
        }
        matches
    }

    /// Validate South Korean Passport format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the passport format is invalid
    pub fn validate_korea_passport(&self, passport: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_korea_passport(passport);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "korea_passport_validation_failed",
                    "Invalid Korea Passport format",
                );
            }
        }
        result
    }

    // =========================================================================
    // BRN — Business Registration Number
    // =========================================================================

    /// Check if value matches a South Korean BRN pattern
    #[must_use]
    pub fn is_korea_brn(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_korea_brn(value);
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

    /// Find all South Korean BRNs in text
    #[must_use]
    pub fn find_korea_brns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_korea_brns_in_text(text);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !matches.is_empty() {
                increment_by(metric_names::detected(), matches.len() as u64);
            }
        }
        matches
    }

    /// Validate South Korean BRN format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the BRN format is invalid
    pub fn validate_korea_brn(&self, brn: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_korea_brn(brn);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn("korea_brn_validation_failed", "Invalid Korea BRN format");
            }
        }
        result
    }

    /// Validate South Korean BRN with weighted mod-10 checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the BRN format or checksum is invalid
    pub fn validate_korea_brn_with_checksum(&self, brn: &str) -> Result<(), Problem> {
        self.inner.validate_korea_brn_with_checksum(brn)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Verified valid samples (birth 900115). Detection (`is_*`) requires the
    // dashed form; the bare 13-digit form is accepted only by validators.
    //   RRN "900115-1234567" — gender digit 1 (citizen), weighted mod-11 check 7.
    //   FRN "900115-5234568" — gender digit 5 (foreigner), check 8.
    //   BRN "123-45-67891" — weighted mod-10 check 1.
    //   DL "11-90-123456-78" — region 11; Passport "M12345678".
    const VALID_RRN: &str = "900115-1234567";
    const VALID_FRN: &str = "900115-5234568";
    const VALID_BRN: &str = "123-45-67891";
    const VALID_DL: &str = "11-90-123456-78";
    const VALID_PASSPORT: &str = "M12345678";

    #[test]
    fn test_rrn() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_korea_rrn(VALID_RRN));
        assert!(!b.is_korea_rrn("123"));
        assert!(b.validate_korea_rrn(VALID_RRN).is_ok());
        // Gender digit 0 is invalid.
        assert!(b.validate_korea_rrn("900115-0234567").is_err());
        assert!(b.validate_korea_rrn_with_checksum(VALID_RRN).is_ok());
        // Tamper the check digit (7 -> 6).
        assert!(
            b.validate_korea_rrn_with_checksum("900115-1234566")
                .is_err()
        );
        assert!(!b.find_korea_rrns_in_text("RRN 900115-1234567").is_empty());
    }

    #[test]
    fn test_rrn_events_enabled() {
        let b = GovernmentBuilder::new();
        assert!(b.is_korea_rrn(VALID_RRN));
        assert!(b.validate_korea_rrn(VALID_RRN).is_ok());
    }

    #[test]
    fn test_frn() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_korea_frn(VALID_FRN));
        assert!(b.validate_korea_frn(VALID_FRN).is_ok());
        // Gender digit 9 is invalid for FRN.
        assert!(b.validate_korea_frn("900115-9234567").is_err());
        assert!(b.validate_korea_frn_with_checksum(VALID_FRN).is_ok());
        // Tamper the check digit (8 -> 7).
        assert!(
            b.validate_korea_frn_with_checksum("900115-5234567")
                .is_err()
        );
        assert!(!b.find_korea_frns_in_text("FRN 900115-5234567").is_empty());
    }

    #[test]
    fn test_brn() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_korea_brn(VALID_BRN));
        assert!(b.validate_korea_brn("123-45-67890").is_ok());
        // 9 digits — wrong length.
        assert!(b.validate_korea_brn("123-45-6789").is_err());
        assert!(b.validate_korea_brn_with_checksum(VALID_BRN).is_ok());
        // Tamper the check digit (1 -> 2).
        assert!(b.validate_korea_brn_with_checksum("123-45-67892").is_err());
        assert!(!b.find_korea_brns_in_text("BRN 123-45-67890").is_empty());
    }

    #[test]
    fn test_driver_license() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_korea_driver_license(VALID_DL));
        assert!(b.validate_korea_driver_license(VALID_DL).is_ok());
        // Region 99 is invalid.
        assert!(b.validate_korea_driver_license("99-90-123456-78").is_err());
        assert!(
            !b.find_korea_driver_licenses_in_text("DL 11-90-123456-78")
                .is_empty()
        );
    }

    #[test]
    fn test_passport() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_korea_passport(VALID_PASSPORT));
        assert!(b.validate_korea_passport(VALID_PASSPORT).is_ok());
        assert!(b.validate_korea_passport("!!!").is_err());
        assert!(
            !b.find_korea_passports_in_text("passport M12345678")
                .is_empty()
        );
    }
}
