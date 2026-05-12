//! UK National Insurance Number (NINO) methods.

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
}
