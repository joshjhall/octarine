//! Nigeria identifier methods — NIN, BVN, and vehicle registration.

use super::*;

impl GovernmentBuilder {
    // ---- NIN ----------------------------------------------------------------

    /// Check if value matches a Nigerian NIN pattern
    #[must_use]
    pub fn is_nigeria_nin(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_nigeria_nin(value);
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

    /// Find all Nigerian NINs in text (label-gated)
    #[must_use]
    pub fn find_nigeria_nins_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_nigeria_nins_in_text(text);
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

    /// Validate Nigerian NIN format (no checksum algorithm exists)
    pub fn validate_nigeria_nin(&self, nin: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_nigeria_nin(nin);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "nigeria_nin_validation_failed",
                    "Invalid Nigeria NIN format",
                );
            }
        }
        result
    }

    // ---- BVN ----------------------------------------------------------------

    /// Check if value matches a Nigerian BVN pattern
    #[must_use]
    pub fn is_nigeria_bvn(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_nigeria_bvn(value);
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

    /// Find all Nigerian BVNs in text (label-gated)
    #[must_use]
    pub fn find_nigeria_bvns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_nigeria_bvns_in_text(text);
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

    /// Validate Nigerian BVN format (no checksum algorithm exists)
    pub fn validate_nigeria_bvn(&self, bvn: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_nigeria_bvn(bvn);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "nigeria_bvn_validation_failed",
                    "Invalid Nigeria BVN format",
                );
            }
        }
        result
    }

    // ---- Vehicle Registration -----------------------------------------------

    /// Check if value matches a Nigerian vehicle registration plate
    #[must_use]
    pub fn is_nigeria_vehicle_registration(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_nigeria_vehicle_registration(value);
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

    /// Find all Nigerian vehicle registration plates in text
    #[must_use]
    pub fn find_nigeria_vehicle_registrations_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_nigeria_vehicle_registrations_in_text(text);
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

    /// Validate a Nigerian vehicle registration plate
    pub fn validate_nigeria_vehicle_registration(&self, reg: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_nigeria_vehicle_registration(reg);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "nigeria_vehicle_reg_validation_failed",
                    "Invalid Nigeria vehicle registration format",
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

    // NIN/BVN are both 11 digits (no public checksum). "LAG123AB" is a
    // current-format Nigerian plate (3 letters + 3 digits + 2 letters).
    const VALID_NIN: &str = "12345678901";
    const VALID_PLATE: &str = "LAG123AB";

    #[test]
    fn test_is_nigeria_nin() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_nigeria_nin(VALID_NIN));
        assert!(!b.is_nigeria_nin("123"));
    }

    #[test]
    fn test_is_nigeria_nin_events_enabled() {
        let b = GovernmentBuilder::new();
        assert!(b.is_nigeria_nin(VALID_NIN));
    }

    #[test]
    fn test_find_nigeria_nins_in_text() {
        let b = GovernmentBuilder::silent();
        // NIN detection is label-gated.
        let matches = b.find_nigeria_nins_in_text("NIN: 12345678901");
        assert!(!matches.is_empty());
        assert!(b.find_nigeria_nins_in_text("nothing").is_empty());
    }

    #[test]
    fn test_validate_nigeria_nin() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_nigeria_nin(VALID_NIN).is_ok());
        // 10 digits — wrong length.
        assert!(b.validate_nigeria_nin("1234567890").is_err());
    }

    #[test]
    fn test_is_nigeria_bvn() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_nigeria_bvn(VALID_NIN));
        assert!(!b.is_nigeria_bvn("123"));
    }

    #[test]
    fn test_find_nigeria_bvns_in_text() {
        let b = GovernmentBuilder::silent();
        let matches = b.find_nigeria_bvns_in_text("BVN: 12345678901");
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_validate_nigeria_bvn() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_nigeria_bvn(VALID_NIN).is_ok());
        assert!(b.validate_nigeria_bvn("1234567890").is_err());
    }

    #[test]
    fn test_is_nigeria_vehicle_registration() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_nigeria_vehicle_registration(VALID_PLATE));
        assert!(!b.is_nigeria_vehicle_registration("!!!"));
    }

    #[test]
    fn test_find_nigeria_vehicle_registrations_in_text() {
        let b = GovernmentBuilder::silent();
        let matches = b.find_nigeria_vehicle_registrations_in_text("plate LAG123AB seen");
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_validate_nigeria_vehicle_registration() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_nigeria_vehicle_registration(VALID_PLATE).is_ok());
        assert!(b.validate_nigeria_vehicle_registration("!!!").is_err());
    }
}
