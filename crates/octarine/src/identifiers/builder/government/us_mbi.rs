//! US Medicare Beneficiary Identifier (MBI) methods.

use super::*;

impl GovernmentBuilder {
    /// Check if value is a valid US Medicare Beneficiary Identifier (MBI)
    ///
    /// Strict — enforces the 11-character CMS layout
    /// (`C A AN N A AN N A A N N`) and the letter alphabet
    /// `ACDEFGHJKMNPQRTUVWXY` (excluding `S, L, O, I, B, Z`). Accepts both the
    /// bare and dashed `XXXX-XXX-XXXX` forms.
    #[must_use]
    pub fn is_us_mbi(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_us_mbi(value);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result {
                increment_by(metric_names::detected(), 1);
                increment_by(metric_names::government_data_found(), 1);
                observe::debug("mbi_detected", "MBI pattern detected");
            }
        }

        result
    }

    /// Find all valid US MBIs in text
    #[must_use]
    pub fn find_us_mbis_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let results = self.inner.find_us_mbis_in_text(text);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !results.is_empty() {
                increment_by(metric_names::detected(), results.len() as u64);
                observe::debug(
                    "mbis_found",
                    format!("Found {} MBI(s) in text", results.len()),
                );
            }
        }

        results
    }

    /// Validate a US MBI format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the MBI length, dash grouping, positional layout,
    /// or letter alphabet is invalid.
    pub fn validate_us_mbi(&self, mbi: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_us_mbi(mbi);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn("mbi_validation_failed", "Invalid MBI format");
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::identifiers::types::IdentifierType;

    // Valid CMS-shaped MBI (Presidio's documented sample). "1AB2C3D4EF5" from
    // the issue is deliberately invalid (excluded letter 'B' at pos 3, and 'F'
    // must be numeric at pos 10).
    const VALID_MBI: &str = "1EG4TE5MK73";
    const VALID_MBI_DASHED: &str = "1EG4-TE5-MK73";
    const INVALID_MBI: &str = "1AB2C3D4EF5";

    #[test]
    fn test_is_us_mbi_valid_invalid() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_us_mbi(VALID_MBI));
        assert!(b.is_us_mbi(VALID_MBI_DASHED));
        assert!(!b.is_us_mbi(INVALID_MBI));
    }

    #[test]
    fn test_find_us_mbis_in_text() {
        let b = GovernmentBuilder::silent();
        let matches = b.find_us_mbis_in_text("Medicare MBI: 1EG4-TE5-MK73 on file");
        assert!(!matches.is_empty());
        assert_eq!(
            matches.first().expect("one match").identifier_type,
            IdentifierType::Mbi
        );
        assert!(b.find_us_mbis_in_text("no mbi here").is_empty());
    }

    #[test]
    fn test_validate_us_mbi() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_us_mbi(VALID_MBI).is_ok());
        assert!(b.validate_us_mbi(INVALID_MBI).is_err());
    }
}
