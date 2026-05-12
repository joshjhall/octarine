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
