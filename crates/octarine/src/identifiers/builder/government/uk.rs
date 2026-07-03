//! UK identifier methods — National Insurance Number (NINO), NHS Number,
//! Passport, Driving Licence (DVLA).

use super::*;

impl GovernmentBuilder {
    /// Check if value is a valid UK National Insurance Number (NINO)
    #[must_use]
    pub fn is_uk_ni(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_uk_ni(value);
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

    /// Find all UK NINOs in text
    #[must_use]
    pub fn find_uk_nis_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let results = self.inner.find_uk_nis_in_text(text);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !results.is_empty() {
                increment_by(metric_names::detected(), results.len() as u64);
                increment_by(metric_names::government_data_found(), results.len() as u64);
                observe::debug(
                    "uk_nis_found",
                    format!("Found {} UK NINO(s) in text", results.len()),
                );
            }
        }
        results
    }

    /// Redact a UK NINO with explicit strategy
    #[must_use]
    pub fn redact_uk_ni_with_strategy(
        &self,
        ni: &str,
        strategy: NationalIdRedactionStrategy,
    ) -> String {
        let start = Instant::now();
        let result = self.inner.redact_uk_ni_with_strategy(ni, strategy);
        if self.emit_events {
            record(
                metric_names::redact_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
        result
    }

    /// Redact all UK NINOs in text with explicit strategy
    ///
    /// Only NINOs that pass HMRC prefix/suffix validation are redacted;
    /// labels ("NI: ", "NINO ", ...) are preserved.
    #[must_use]
    pub fn redact_uk_nis_in_text_with_strategy(
        &self,
        text: &str,
        strategy: NationalIdRedactionStrategy,
    ) -> String {
        let start = Instant::now();
        let result = self
            .inner
            .redact_uk_nis_in_text_with_strategy(text, strategy);
        if self.emit_events {
            record(
                metric_names::redact_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
        result
    }

    // ----------------------------------------------------------------------
    // UK NHS Number — 10 digits, mod-11 weighted checksum
    //
    // NHS Numbers are HIPAA PHI under SAFE HARBOR and GDPR Article 9 special
    // category data; classification flags live in `observe::pii`.
    // ----------------------------------------------------------------------

    /// Check if value matches the UK NHS Number format (10 digits)
    #[must_use]
    pub fn is_uk_nhs(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_uk_nhs(value);
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

    /// Find all UK NHS Numbers in text (label-anchored or grouped form)
    #[must_use]
    pub fn find_uk_nhs_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let results = self.inner.find_uk_nhs_in_text(text);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !results.is_empty() {
                increment_by(metric_names::detected(), results.len() as u64);
                increment_by(metric_names::government_data_found(), results.len() as u64);
                observe::debug(
                    "uk_nhs_found",
                    format!("Found {} UK NHS Number(s) in text", results.len()),
                );
            }
        }
        results
    }

    /// Validate UK NHS Number format
    pub fn validate_uk_nhs(&self, value: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_uk_nhs(value);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn("uk_nhs_validation_failed", "Invalid UK NHS Number format");
            }
        }
        result
    }

    /// Validate UK NHS Number including the mod-11 weighted checksum
    pub fn validate_uk_nhs_with_checksum(&self, value: &str) -> Result<(), Problem> {
        self.inner.validate_uk_nhs_with_checksum(value)
    }

    // ----------------------------------------------------------------------
    // UK Passport — 2 letters + 7 digits
    // ----------------------------------------------------------------------

    /// Check if value matches the UK passport format
    #[must_use]
    pub fn is_uk_passport(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_uk_passport(value);
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

    /// Find all UK passport patterns in text (label-anchored)
    #[must_use]
    pub fn find_uk_passports_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let results = self.inner.find_uk_passports_in_text(text);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !results.is_empty() {
                increment_by(metric_names::detected(), results.len() as u64);
                increment_by(metric_names::government_data_found(), results.len() as u64);
                observe::debug(
                    "uk_passports_found",
                    format!("Found {} UK passport(s) in text", results.len()),
                );
            }
        }
        results
    }

    /// Validate UK passport format
    pub fn validate_uk_passport(&self, value: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_uk_passport(value);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "uk_passport_validation_failed",
                    "Invalid UK passport format",
                );
            }
        }
        result
    }

    // ----------------------------------------------------------------------
    // UK Driving Licence (DVLA) — 16-char structural shape
    // ----------------------------------------------------------------------

    /// Check if value matches the UK DVLA driving licence format
    #[must_use]
    pub fn is_uk_driving_licence(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_uk_driving_licence(value);
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

    /// Find all UK DVLA driving licence patterns in text (label-anchored)
    #[must_use]
    pub fn find_uk_driving_licences_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let results = self.inner.find_uk_driving_licences_in_text(text);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !results.is_empty() {
                increment_by(metric_names::detected(), results.len() as u64);
                increment_by(metric_names::government_data_found(), results.len() as u64);
                observe::debug(
                    "uk_driving_licences_found",
                    format!("Found {} UK driving licence(s) in text", results.len()),
                );
            }
        }
        results
    }

    /// Validate UK DVLA driving licence shape
    pub fn validate_uk_driving_licence(&self, value: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_uk_driving_licence(value);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "uk_driving_licence_validation_failed",
                    "Invalid UK driving licence format",
                );
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Verified valid samples:
    //   NINO "AB123456C" — allowed prefix, suffix A-D.
    //   NHS "9434765919" — canonical NHS Digital test number (mod-11 check).
    //   Passport "AB1234567" — 2 letters + 7 digits.
    //   Driving licence "MORGA753116SM9IJ" — 16-char DVLA structural shape.
    const VALID_NINO: &str = "AB123456C";
    const VALID_NHS: &str = "9434765919";
    const VALID_PASSPORT: &str = "AB1234567";
    const VALID_DL: &str = "MORGA753116SM9IJ";

    #[test]
    fn test_uk_ni() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_uk_ni(VALID_NINO));
        // "BG" is a disallowed NINO prefix.
        assert!(!b.is_uk_ni("BG123456C"));
        assert!(!b.find_uk_nis_in_text("NI AB123456C").is_empty());
    }

    #[test]
    fn test_uk_ni_events_enabled() {
        let b = GovernmentBuilder::new();
        assert!(b.is_uk_ni(VALID_NINO));
    }

    #[test]
    fn test_redact_uk_ni_with_strategy() {
        let b = GovernmentBuilder::silent();
        assert_eq!(
            b.redact_uk_ni_with_strategy(VALID_NINO, NationalIdRedactionStrategy::Token),
            "[NATIONAL_ID]"
        );
    }

    #[test]
    fn test_redact_uk_nis_in_text_with_strategy() {
        let b = GovernmentBuilder::silent();
        let out = b.redact_uk_nis_in_text_with_strategy(
            "NI AB123456C",
            NationalIdRedactionStrategy::Token,
        );
        assert!(out.contains("[NATIONAL_ID]"));
        assert!(!out.contains("AB123456C"));
    }

    #[test]
    fn test_uk_nhs() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_uk_nhs(VALID_NHS));
        assert!(b.validate_uk_nhs(VALID_NHS).is_ok());
        // 9 digits — wrong length.
        assert!(b.validate_uk_nhs("943476591").is_err());
        assert!(b.validate_uk_nhs_with_checksum(VALID_NHS).is_ok());
        // Flip last digit so the mod-11 checksum fails.
        assert!(b.validate_uk_nhs_with_checksum("9434765910").is_err());
        assert!(!b.find_uk_nhs_in_text("NHS 943 476 5919").is_empty());
    }

    #[test]
    fn test_uk_passport() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_uk_passport(VALID_PASSPORT));
        assert!(b.validate_uk_passport(VALID_PASSPORT).is_ok());
        assert!(b.validate_uk_passport("!!!").is_err());
        assert!(!b.find_uk_passports_in_text("passport AB1234567").is_empty());
    }

    #[test]
    fn test_uk_driving_licence() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_uk_driving_licence(VALID_DL));
        assert!(b.validate_uk_driving_licence(VALID_DL).is_ok());
        assert!(b.validate_uk_driving_licence("too-short").is_err());
        // Detection is label-anchored ("driving licence", "DVLA", ...).
        assert!(
            !b.find_uk_driving_licences_in_text("driving licence MORGA753116SM9IJ")
                .is_empty()
        );
    }
}
