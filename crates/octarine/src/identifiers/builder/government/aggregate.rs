//! Aggregate (cross-cutting) government identifier methods.

use super::*;

impl GovernmentBuilder {
    /// Check if value is any government identifier
    #[must_use]
    pub fn is_government_identifier(&self, value: &str) -> bool {
        self.inner.is_government_identifier(value)
    }

    /// Check if text contains any government identifier
    pub fn is_government_present(&self, text: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_government_present(text);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result {
                increment_by(metric_names::government_data_found(), 1);
                observe::debug(
                    "government_id_detected",
                    "Government identifier present in text",
                );
            }
        }

        result
    }

    /// Find all government IDs in text
    #[must_use]
    pub fn find_all_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let results = self.inner.find_all_in_text(text);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !results.is_empty() {
                increment_by(metric_names::detected(), results.len() as u64);
            }
        }

        results
    }

    /// Redact all government IDs in text with explicit policy
    ///
    /// # Arguments
    ///
    /// * `text` - The text to scan for government identifiers
    /// * `policy` - The redaction policy to apply
    #[must_use]
    pub fn redact_all_in_text_with_policy(
        &self,
        text: &str,
        policy: crate::identifiers::types::GovernmentTextPolicy,
    ) -> String {
        let start = Instant::now();
        let result = self.inner.redact_all_in_text_with_policy(text, policy);

        if self.emit_events {
            record(
                metric_names::redact_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }

        result
    }
}
