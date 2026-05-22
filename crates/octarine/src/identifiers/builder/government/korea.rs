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
