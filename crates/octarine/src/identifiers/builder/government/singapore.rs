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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // "S1234567D" is an NRIC whose check letter (D) is computed with the
    // official weighted mod-11 algorithm for the S-prefix table.
    // "12345678K" is a valid UEN business layout.
    const VALID_NRIC: &str = "S1234567D";
    const VALID_UEN: &str = "12345678K";

    #[test]
    fn test_is_singapore_nric() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_singapore_nric(VALID_NRIC));
        assert!(!b.is_singapore_nric("not-a-nric"));
    }

    #[test]
    fn test_is_singapore_nric_events_enabled() {
        let b = GovernmentBuilder::new();
        assert!(b.is_singapore_nric(VALID_NRIC));
    }

    #[test]
    fn test_find_singapore_nrics_in_text() {
        let b = GovernmentBuilder::silent();
        let matches = b.find_singapore_nrics_in_text("NRIC S1234567D on file");
        assert!(!matches.is_empty());
        assert!(b.find_singapore_nrics_in_text("nothing").is_empty());
    }

    #[test]
    fn test_validate_singapore_nric() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_singapore_nric(VALID_NRIC).is_ok());
        // Invalid prefix 'A'.
        assert!(b.validate_singapore_nric("A1234567B").is_err());
        // 8 chars — wrong length.
        assert!(b.validate_singapore_nric("S123456A").is_err());
    }

    #[test]
    fn test_validate_singapore_nric_with_checksum() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_singapore_nric_with_checksum(VALID_NRIC).is_ok());
        // Wrong check letter (D is correct, use A).
        assert!(
            b.validate_singapore_nric_with_checksum("S1234567A")
                .is_err()
        );
    }

    #[test]
    fn test_is_singapore_uen() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_singapore_uen(VALID_UEN));
        assert!(!b.is_singapore_uen("!!!"));
    }

    #[test]
    fn test_find_singapore_uens_in_text() {
        let b = GovernmentBuilder::silent();
        let matches = b.find_singapore_uens_in_text("UEN 12345678K registered");
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_validate_singapore_uen() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_singapore_uen(VALID_UEN).is_ok());
        assert!(b.validate_singapore_uen("12345678K201912345K").is_err());
    }
}
