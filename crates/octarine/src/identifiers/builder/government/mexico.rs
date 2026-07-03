//! Mexico CURP methods.

use super::*;

impl GovernmentBuilder {
    /// Check if value matches a Mexican CURP pattern
    #[must_use]
    pub fn is_mexico_curp(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_mexico_curp(value);
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

    /// Find all Mexican CURPs in text
    #[must_use]
    pub fn find_mexico_curps_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_mexico_curps_in_text(text);
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

    /// Validate Mexican CURP format (without checksum)
    pub fn validate_mexico_curp(&self, curp: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_mexico_curp(curp);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "mexico_curp_validation_failed",
                    "Invalid Mexico CURP format",
                );
            }
        }
        result
    }

    /// Validate Mexican CURP with check digit verification
    pub fn validate_mexico_curp_with_checksum(&self, curp: &str) -> Result<(), Problem> {
        self.inner.validate_mexico_curp_with_checksum(curp)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // "BADD110313HDFLNS04" is a structurally valid CURP (state DF, gender H)
    // whose final check digit (4) is computed with the official weighted
    // mod-10 algorithm over the first 17 characters.
    const VALID_CURP: &str = "BADD110313HDFLNS04";

    #[test]
    fn test_is_mexico_curp() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_mexico_curp(VALID_CURP));
        assert!(!b.is_mexico_curp("not-a-curp"));
    }

    #[test]
    fn test_is_mexico_curp_events_enabled() {
        let b = GovernmentBuilder::new();
        assert!(b.is_mexico_curp(VALID_CURP));
    }

    #[test]
    fn test_find_mexico_curps_in_text() {
        let b = GovernmentBuilder::silent();
        let matches = b.find_mexico_curps_in_text("CURP BADD110313HDFLNS04 valida");
        assert!(!matches.is_empty());
        assert!(b.find_mexico_curps_in_text("nada").is_empty());
    }

    #[test]
    fn test_validate_mexico_curp() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_mexico_curp(VALID_CURP).is_ok());
        // 16 chars — wrong length.
        assert!(b.validate_mexico_curp("BADD110313HDFLNS").is_err());
        // Invalid state code ZZ.
        assert!(b.validate_mexico_curp("BADD110313HZZLNS09").is_err());
    }

    #[test]
    fn test_validate_mexico_curp_with_checksum() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_mexico_curp_with_checksum(VALID_CURP).is_ok());
        // Tamper the check digit (4 -> 5).
        assert!(
            b.validate_mexico_curp_with_checksum("BADD110313HDFLNS05")
                .is_err()
        );
    }
}
