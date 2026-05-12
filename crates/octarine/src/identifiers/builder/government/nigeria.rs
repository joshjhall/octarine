//! Nigeria NIN methods.

use super::*;

impl GovernmentBuilder {
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
}
