//! Aggregate (cross-domain) operations on `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value is any government identifier
    #[must_use]
    pub fn is_government_identifier(&self, value: &str) -> bool {
        detection::is_government_identifier(value)
    }

    /// Check if text contains any government identifier
    #[must_use]
    pub fn is_government_present(&self, text: &str) -> bool {
        detection::is_government_present(text)
    }

    /// Find all government IDs in text
    #[must_use]
    pub fn find_all_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_all_government_ids_in_text(text)
    }

    /// Redact all government IDs in text with explicit policy
    ///
    /// # Arguments
    ///
    /// * `text` - The text to scan for government identifiers
    /// * `policy` - The redaction policy to apply
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use crate::primitives::identifiers::government::{
    ///     GovernmentIdentifierBuilder, TextRedactionPolicy,
    /// };
    ///
    /// let builder = GovernmentIdentifierBuilder::new();
    ///
    /// // Complete - use type tokens like [SSN], [VEHICLE_ID]
    /// let result = builder.redact_all_in_text_with_policy(
    ///     "SSN: 517-29-8346",
    ///     TextRedactionPolicy::Complete,
    /// );
    /// assert!(result.contains("[SSN]"));
    ///
    /// // Partial - shows last 4 digits for SSN
    /// let result = builder.redact_all_in_text_with_policy(
    ///     "SSN: 517-29-8346",
    ///     TextRedactionPolicy::Partial,
    /// );
    /// assert!(result.contains("***-**-0001"));
    /// ```
    #[must_use]
    pub fn redact_all_in_text_with_policy(
        &self,
        text: &str,
        policy: TextRedactionPolicy,
    ) -> String {
        sanitization::redact_all_government_ids_in_text_with_policy(text, Some(policy))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    fn builder() -> GovernmentIdentifierBuilder {
        GovernmentIdentifierBuilder::new()
    }

    #[test]
    fn test_aggregate_operations() {
        let gov = builder();

        // Detection
        assert!(gov.is_government_identifier("517-29-8346"));
        assert!(gov.is_government_present("SSN: 517-29-8346"));

        // Redaction with policy
        let text = "SSN: 517-29-8346, VIN: 1HGBH41JXMN109186";
        let redacted = gov.redact_all_in_text_with_policy(text, TextRedactionPolicy::Complete);
        assert!(redacted.contains("[SSN]"));
        assert!(redacted.contains("[VEHICLE_ID]"));
    }
}
