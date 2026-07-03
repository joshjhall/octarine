//! SSN methods.

use super::*;

impl GovernmentBuilder {
    /// Check if value is an SSN
    pub fn is_ssn(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_ssn(value);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result {
                increment_by(metric_names::detected(), 1);
                increment_by(metric_names::government_data_found(), 1);
                observe::debug("ssn_detected", "SSN pattern detected");
            }
        }

        result
    }

    /// Find all SSNs in text
    #[must_use]
    pub fn find_ssns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let results = self.inner.find_ssns_in_text(text);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !results.is_empty() {
                increment_by(metric_names::detected(), results.len() as u64);
                observe::debug(
                    "ssns_found",
                    format!("Found {} SSN(s) in text", results.len()),
                );
            }
        }

        results
    }

    /// Validate SSN format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the SSN format is invalid
    pub fn validate_ssn(&self, ssn: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_ssn(ssn);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn("ssn_validation_failed", "Invalid SSN format");
            }
        }

        result
    }

    /// Check if SSN is in ITIN area range
    #[must_use]
    pub fn is_itin_area(&self, ssn: &str) -> bool {
        self.inner.is_itin_area(ssn)
    }

    /// Redact an SSN with explicit strategy
    #[must_use]
    pub fn redact_ssn_with_strategy(&self, ssn: &str, strategy: SsnRedactionStrategy) -> String {
        self.inner.redact_ssn_with_strategy(ssn, strategy)
    }

    /// Redact all SSNs in text with explicit strategy
    #[must_use]
    pub fn redact_ssns_in_text_with_strategy(
        &self,
        text: &str,
        strategy: SsnRedactionStrategy,
    ) -> String {
        self.inner.redact_ssns_in_text_with_strategy(text, strategy)
    }

    /// Normalize an SSN (remove formatting)
    #[must_use]
    pub fn normalize_ssn(&self, ssn: &str) -> String {
        self.inner.normalize_ssn(ssn)
    }

    /// Convert SSN to standard hyphenated format
    #[must_use]
    pub fn to_ssn_with_hyphens(&self, ssn: &str) -> String {
        self.inner.to_ssn_with_hyphens(ssn)
    }

    /// Convert SSN to safe display format (masked)
    #[must_use]
    pub fn to_ssn_display(&self, ssn: &str) -> String {
        self.inner.to_ssn_display(ssn)
    }

    /// Sanitize an SSN (normalize + validate)
    pub fn sanitize_ssn(&self, ssn: &str) -> Result<String, Problem> {
        self.inner.sanitize_ssn(ssn)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::identifiers::types::IdentifierType;

    // "517-29-8346" is a structurally valid SSN (area 517, group 29,
    // serial 8346) used in the primitive detection tests. "000-12-3456"
    // is invalid because area 000 is never assigned.
    const VALID_SSN: &str = "517-29-8346";
    const INVALID_SSN: &str = "000-12-3456";

    #[test]
    fn test_is_ssn_valid_and_invalid() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_ssn(VALID_SSN));
        assert!(!b.is_ssn(INVALID_SSN));
        assert!(!b.is_ssn("not-an-ssn"));
    }

    #[test]
    fn test_is_ssn_events_enabled_path() {
        // Exercise the emit_events branch (metrics + debug event).
        let b = GovernmentBuilder::new();
        assert!(b.is_ssn(VALID_SSN));
    }

    #[test]
    fn test_validate_ssn() {
        let b = GovernmentBuilder::silent();
        // 234-56-7890 is a valid SSN per primitive validation tests.
        assert!(b.validate_ssn("234-56-7890").is_ok());
        assert!(b.validate_ssn(INVALID_SSN).is_err());
    }

    #[test]
    fn test_validate_ssn_events_enabled() {
        let b = GovernmentBuilder::new();
        assert!(b.validate_ssn("234-56-7890").is_ok());
        assert!(b.validate_ssn(INVALID_SSN).is_err());
    }

    #[test]
    fn test_find_ssns_in_text() {
        let b = GovernmentBuilder::silent();
        let matches = b.find_ssns_in_text("my ssn is 517-29-8346 ok");
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches.first().expect("one match").identifier_type,
            IdentifierType::Ssn
        );
        assert!(b.find_ssns_in_text("nothing here").is_empty());
    }

    #[test]
    fn test_is_itin_area() {
        let b = GovernmentBuilder::silent();
        // ITINs have area 9XX; a normal SSN area is not in the ITIN range.
        assert!(b.is_itin_area("900-70-0001"));
        assert!(!b.is_itin_area(VALID_SSN));
    }

    #[test]
    fn test_redact_ssn_with_strategy() {
        let b = GovernmentBuilder::silent();
        assert_eq!(
            b.redact_ssn_with_strategy(VALID_SSN, SsnRedactionStrategy::Token),
            "[SSN]"
        );
        assert_eq!(
            b.redact_ssn_with_strategy(VALID_SSN, SsnRedactionStrategy::LastFour),
            "***-**-8346"
        );
        assert_eq!(
            b.redact_ssn_with_strategy(VALID_SSN, SsnRedactionStrategy::Mask),
            "***-**-****"
        );
    }

    #[test]
    fn test_redact_ssns_in_text_with_strategy() {
        let b = GovernmentBuilder::silent();
        let out =
            b.redact_ssns_in_text_with_strategy("ssn 517-29-8346", SsnRedactionStrategy::Token);
        assert!(out.contains("[SSN]"));
        assert!(!out.contains("517-29-8346"));
    }

    #[test]
    fn test_normalize_and_convert_ssn() {
        let b = GovernmentBuilder::silent();
        assert_eq!(b.normalize_ssn("517-29-8346"), "517298346");
        assert_eq!(b.to_ssn_with_hyphens("517298346"), "517-29-8346");
        assert_eq!(b.to_ssn_display("517-29-8346"), "***-**-8346");
    }

    #[test]
    fn test_sanitize_ssn() {
        let b = GovernmentBuilder::silent();
        assert_eq!(b.sanitize_ssn("517-29-8346").expect("valid"), "517-29-8346");
        assert!(b.sanitize_ssn(INVALID_SSN).is_err());
    }
}
