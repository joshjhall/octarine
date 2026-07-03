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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // "1234567890121" is a 13-digit TNIN whose final check digit (1) is
    // computed with the official weighted mod-11 algorithm over the first
    // 12 digits.
    const VALID_TNIN: &str = "1234567890121";

    #[test]
    fn test_is_thailand_tnin() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_thailand_tnin(VALID_TNIN));
        assert!(!b.is_thailand_tnin("not-a-tnin"));
    }

    #[test]
    fn test_is_thailand_tnin_events_enabled() {
        let b = GovernmentBuilder::new();
        assert!(b.is_thailand_tnin(VALID_TNIN));
    }

    #[test]
    fn test_find_thailand_tnins_in_text() {
        let b = GovernmentBuilder::silent();
        let matches = b.find_thailand_tnins_in_text("TNIN 1234567890121 ok");
        assert!(!matches.is_empty());
        assert!(b.find_thailand_tnins_in_text("nothing").is_empty());
    }

    #[test]
    fn test_validate_thailand_tnin() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_thailand_tnin(VALID_TNIN).is_ok());
        // 10 digits — wrong length.
        assert!(b.validate_thailand_tnin("1234567890").is_err());
        // All-identical digits are rejected.
        assert!(b.validate_thailand_tnin("1111111111111").is_err());
    }

    #[test]
    fn test_validate_thailand_tnin_with_checksum() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_thailand_tnin_with_checksum(VALID_TNIN).is_ok());
        // Tamper the check digit (1 -> 2).
        assert!(
            b.validate_thailand_tnin_with_checksum("1234567890122")
                .is_err()
        );
    }
}
