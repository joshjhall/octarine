//! Personal identifier builder with observability
//!
//! Wraps `primitives::data::identifiers::PersonalIdentifierBuilder` with observe instrumentation.
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.

use std::time::Instant;

use crate::observe;
use crate::observe::Problem;
use crate::observe::metrics::{MetricName, increment_by, record};
use crate::primitives::identifiers::{
    BirthdateRedactionStrategy, EmailRedactionStrategy, NameRedactionStrategy,
    PersonalIdentifierBuilder as PrimitivePersonalBuilder, PersonalTextPolicy, PhoneFormatStyle,
    PhoneRedactionStrategy, UsernameRedactionStrategy,
};

use super::super::types::{IdentifierMatch, IdentifierType, PhoneRegion};

// Pre-validated metric names
#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;

    pub fn detect_ms() -> MetricName {
        MetricName::new("data.identifiers.personal.detect_ms").expect("valid metric name")
    }

    pub fn validate_ms() -> MetricName {
        MetricName::new("data.identifiers.personal.validate_ms").expect("valid metric name")
    }

    pub fn redact_ms() -> MetricName {
        MetricName::new("data.identifiers.personal.redact_ms").expect("valid metric name")
    }

    pub fn detected() -> MetricName {
        MetricName::new("data.identifiers.personal.detected").expect("valid metric name")
    }

    pub fn pii_found() -> MetricName {
        MetricName::new("data.identifiers.personal.pii_found").expect("valid metric name")
    }
}

/// Personal identifier builder with observability
///
/// Provides detection, validation, and sanitization for personal identifiers
/// (emails, phones, names, birthdates) with full audit trail via observe.
#[derive(Debug, Clone, Copy, Default)]
pub struct PersonalBuilder {
    inner: PrimitivePersonalBuilder,
    emit_events: bool,
}

impl PersonalBuilder {
    /// Create a new PersonalBuilder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: PrimitivePersonalBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: PrimitivePersonalBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // ========================================================================
    // Detection Methods
    // ========================================================================

    /// Detect personal identifier type from value
    #[must_use]
    pub fn detect(&self, value: &str) -> Option<IdentifierType> {
        let start = Instant::now();
        let result = self.inner.find(value);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if result.is_some() {
                increment_by(metric_names::detected(), 1);
            }
        }

        result
    }

    /// Check if value is a personal identifier
    #[must_use]
    pub fn is_personal_identifier(&self, value: &str) -> bool {
        self.inner.is_personal_identifier(value)
    }

    /// Check if value is an email address
    #[must_use]
    pub fn is_email(&self, value: &str) -> bool {
        self.inner.is_email(value)
    }

    /// Check if value is a phone number
    #[must_use]
    pub fn is_phone_number(&self, value: &str) -> bool {
        self.inner.is_phone_number(value)
    }

    /// Check if value is a personal name
    #[must_use]
    pub fn is_name(&self, value: &str) -> bool {
        self.inner.is_name(value)
    }

    /// Check if value is a birthdate
    #[must_use]
    pub fn is_birthdate(&self, value: &str) -> bool {
        self.inner.is_birthdate(value)
    }

    /// Check if value is PII
    pub fn is_pii(&self, value: &str) -> bool {
        let result = self.inner.is_pii(value);

        if self.emit_events && result {
            increment_by(metric_names::pii_found(), 1);
        }

        result
    }

    /// Check if text contains any personal identifiers
    pub fn is_pii_present(&self, text: &str) -> bool {
        let result = self.inner.is_pii_present(text);

        if self.emit_events && result {
            increment_by(metric_names::pii_found(), 1);
            observe::warn("personal_pii_detected", "Personal PII detected in text");
        }

        result
    }

    /// Find all emails in text
    #[must_use]
    pub fn find_emails_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let matches = self.inner.detect_emails_in_text(text);

        if self.emit_events && !matches.is_empty() {
            increment_by(metric_names::detected(), matches.len() as u64);
        }

        matches
    }

    /// Find all phones in text
    #[must_use]
    pub fn find_phones_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let matches = self.inner.detect_phones_in_text(text);

        if self.emit_events && !matches.is_empty() {
            increment_by(metric_names::detected(), matches.len() as u64);
        }

        matches
    }

    /// Find all names in text
    #[must_use]
    pub fn find_names_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.detect_names_in_text(text)
    }

    /// Find all birthdates in text
    #[must_use]
    pub fn find_birthdates_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.detect_birthdates_in_text(text)
    }

    /// Find all personal identifiers in text
    #[must_use]
    pub fn find_all_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let matches = self.inner.detect_all_in_text(text);

        if self.emit_events && !matches.is_empty() {
            increment_by(metric_names::pii_found(), matches.len() as u64);
            observe::info(
                "personal_pii_scan_complete",
                format!("Found {} personal identifiers", matches.len()),
            );
        }

        matches
    }

    /// Detect phone region
    #[must_use]
    pub fn find_phone_region(&self, phone: &str) -> Option<PhoneRegion> {
        self.inner.find_phone_region(phone)
    }

    // ========================================================================
    // Validation Methods
    // ========================================================================

    /// Validate email format (returns Result)
    pub fn validate_email(&self, email: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_email(email);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if result.is_err() {
                observe::debug("email_validation_failed", "Email validation failed");
            }
        }

        result
    }

    /// Validate phone format (returns Result with region)
    pub fn validate_phone(&self, phone: &str) -> Result<PhoneRegion, Problem> {
        let start = Instant::now();
        let result = self.inner.validate_phone(phone);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }

        result
    }

    /// Validate username format (returns Result)
    pub fn validate_username(&self, username: &str) -> Result<(), Problem> {
        self.inner.validate_username(username)
    }

    /// Validate birthdate format (returns Result)
    pub fn validate_birthdate(&self, date: &str) -> Result<(), Problem> {
        self.inner.validate_birthdate(date)
    }

    /// Validate name format (returns Result)
    pub fn validate_name(&self, name: &str) -> Result<(), Problem> {
        self.inner.validate_name(name)
    }

    // ========================================================================
    // Sanitization Methods
    // ========================================================================

    /// Redact email with explicit strategy
    #[must_use]
    pub fn redact_email_with_strategy(
        &self,
        email: &str,
        strategy: EmailRedactionStrategy,
    ) -> String {
        self.inner.redact_email_with_strategy(email, strategy)
    }

    /// Redact phone with explicit strategy
    #[must_use]
    pub fn redact_phone_with_strategy(
        &self,
        phone: &str,
        strategy: PhoneRedactionStrategy,
    ) -> String {
        self.inner.redact_phone_with_strategy(phone, strategy)
    }

    /// Redact username with explicit strategy
    #[must_use]
    pub fn redact_username_with_strategy(
        &self,
        username: &str,
        strategy: UsernameRedactionStrategy,
    ) -> String {
        self.inner.redact_username_with_strategy(username, strategy)
    }

    /// Redact name with explicit strategy
    #[must_use]
    pub fn redact_name_with_strategy(&self, name: &str, strategy: NameRedactionStrategy) -> String {
        self.inner.redact_name_with_strategy(name, strategy)
    }

    /// Redact birthdate with explicit strategy
    #[must_use]
    pub fn redact_birthdate_with_strategy(
        &self,
        date: &str,
        strategy: BirthdateRedactionStrategy,
    ) -> String {
        self.inner.redact_birthdate_with_strategy(date, strategy)
    }

    /// Sanitize email (validate and normalize)
    pub fn sanitize_email(&self, email: &str) -> Result<String, Problem> {
        self.inner.sanitize_email(email)
    }

    /// Sanitize phone (validate and normalize to E.164)
    pub fn sanitize_phone(&self, phone: &str) -> Result<String, Problem> {
        self.inner.sanitize_phone(phone)
    }

    /// Sanitize name (validate and normalize)
    pub fn sanitize_name(&self, name: &str) -> Result<String, Problem> {
        self.inner.sanitize_name(name)
    }

    /// Sanitize birthdate (validate and normalize to ISO 8601)
    pub fn sanitize_birthdate(&self, date: &str) -> Result<String, Problem> {
        self.inner.sanitize_birthdate(date)
    }

    /// Redact all emails in text with explicit policy
    #[must_use]
    pub fn redact_emails_in_text_with_policy(
        &self,
        text: &str,
        policy: PersonalTextPolicy,
    ) -> String {
        self.inner.redact_emails_in_text_with_policy(text, policy)
    }

    /// Redact all emails in text with strategy
    #[must_use]
    pub fn redact_emails_in_text_with_strategy(
        &self,
        text: &str,
        strategy: EmailRedactionStrategy,
    ) -> String {
        self.inner
            .redact_emails_in_text_with_strategy(text, strategy)
    }

    /// Redact all phones in text with explicit policy
    #[must_use]
    pub fn redact_phones_in_text_with_policy(
        &self,
        text: &str,
        policy: PersonalTextPolicy,
    ) -> String {
        self.inner.redact_phones_in_text_with_policy(text, policy)
    }

    /// Redact all phones in text with strategy
    #[must_use]
    pub fn redact_phones_in_text_with_strategy(
        &self,
        text: &str,
        strategy: PhoneRedactionStrategy,
    ) -> String {
        self.inner
            .redact_phones_in_text_with_strategy(text, strategy)
    }

    /// Redact all names in text with explicit policy
    #[must_use]
    pub fn redact_names_in_text_with_policy(
        &self,
        text: &str,
        policy: PersonalTextPolicy,
    ) -> String {
        self.inner.redact_names_in_text_with_policy(text, policy)
    }

    /// Redact all birthdates in text with explicit policy
    #[must_use]
    pub fn redact_birthdates_in_text_with_policy(
        &self,
        text: &str,
        policy: PersonalTextPolicy,
    ) -> String {
        self.inner
            .redact_birthdates_in_text_with_policy(text, policy)
    }

    /// Redact all personal identifiers in text with explicit policy
    ///
    /// # Arguments
    ///
    /// * `text` - The text to scan for personal identifiers
    /// * `policy` - The redaction policy to apply
    #[must_use]
    pub fn redact_all_in_text_with_policy(&self, text: &str, policy: PersonalTextPolicy) -> String {
        let start = Instant::now();
        let result = self.inner.redact_all_in_text_with_policy(text, policy);

        if self.emit_events {
            record(
                metric_names::redact_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if result != text {
                observe::info("personal_pii_redacted", "Personal PII redacted from text");
            }
        }

        result
    }

    // ========================================================================
    // Conversion Methods
    // ========================================================================

    /// Normalize phone to E.164 format
    pub fn normalize_phone_e164(
        &self,
        phone: &str,
        default_country: &str,
    ) -> Result<String, Problem> {
        self.inner.normalize_phone_e164(phone, default_country)
    }

    /// Format phone for display
    #[must_use]
    #[allow(clippy::wrong_self_convention)] // Builder pattern uses &self consistently
    pub fn to_phone_display(&self, phone: &str, style: PhoneFormatStyle) -> String {
        self.inner.to_phone_display(phone, style)
    }

    /// Normalize email address
    pub fn normalize_email(&self, email: &str) -> Result<String, Problem> {
        self.inner.normalize_email(email)
    }

    /// Calculate age from birthdate
    pub fn calculate_age(&self, birthdate: &str) -> Result<u32, Problem> {
        self.inner.calculate_age(birthdate)
    }

    // ========================================================================
    // Test Pattern Detection
    // ========================================================================

    /// Check if email is a test pattern
    #[must_use]
    pub fn is_test_email(&self, email: &str) -> bool {
        self.inner.is_test_email(email)
    }

    /// Check if phone is a test pattern
    #[must_use]
    pub fn is_test_phone(&self, phone: &str) -> bool {
        self.inner.is_test_phone(phone)
    }

    /// Check if birthdate is a known test/sample pattern
    ///
    /// Detects common placeholder dates like Unix epoch (1970-01-01),
    /// Y2K (2000-01-01), and other frequently used test dates.
    /// The date must be valid (parseable and in the past) to be considered.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::identifiers::PersonalBuilder;
    ///
    /// let builder = PersonalBuilder::new();
    /// assert!(builder.is_test_birthdate("1970-01-01")); // Unix epoch
    /// assert!(builder.is_test_birthdate("2000-01-01")); // Y2K
    /// assert!(!builder.is_test_birthdate("1985-07-23")); // Real-looking date
    /// ```
    #[must_use]
    pub fn is_test_birthdate(&self, date: &str) -> bool {
        self.inner.is_test_birthdate(date)
    }

    // =========================================================================
    // Cache Management
    // =========================================================================

    /// Get combined cache statistics for all personal identifier caches
    ///
    /// Returns aggregated stats across email and phone validation caches.
    /// Use this for overall module performance monitoring.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::identifiers::PersonalBuilder;
    ///
    /// let builder = PersonalBuilder::new();
    /// let stats = builder.cache_stats();
    ///
    /// println!("Cache size: {}/{}", stats.size, stats.capacity);
    /// println!("Hit rate: {:.1}%", stats.hit_rate());
    /// ```
    #[must_use]
    pub fn cache_stats(&self) -> super::super::types::CacheStats {
        self.inner.cache_stats()
    }

    /// Get email validation cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn email_cache_stats(&self) -> super::super::types::CacheStats {
        self.inner.email_cache_stats()
    }

    /// Get phone validation cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn phone_cache_stats(&self) -> super::super::types::CacheStats {
        self.inner.phone_cache_stats()
    }

    /// Clear all personal identifier caches
    ///
    /// Use this to reset cache state, typically for testing or memory management.
    pub fn clear_caches(&self) {
        self.inner.clear_caches();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = PersonalBuilder::new();
        assert!(builder.emit_events);

        let silent = PersonalBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = PersonalBuilder::new().with_events(false);
        assert!(!builder.emit_events);

        let builder = PersonalBuilder::silent().with_events(true);
        assert!(builder.emit_events);
    }

    #[test]
    fn test_email_detection() {
        let builder = PersonalBuilder::silent();
        assert!(builder.is_email("user@example.com"));
    }

    #[test]
    fn test_detect_email() {
        let builder = PersonalBuilder::silent();
        assert_eq!(
            builder.detect("user@example.com"),
            Some(IdentifierType::Email)
        );
    }

    #[test]
    fn test_detect_phone() {
        let builder = PersonalBuilder::silent();
        assert_eq!(
            builder.detect("+15551234567"),
            Some(IdentifierType::PhoneNumber)
        );
    }

    #[test]
    fn test_redact_email_with_strategy() {
        let builder = PersonalBuilder::silent();
        assert_eq!(
            builder
                .redact_email_with_strategy("user@example.com", EmailRedactionStrategy::ShowFirst),
            "u***@example.com"
        );
    }

    #[test]
    fn test_redact_phone_with_strategy() {
        let builder = PersonalBuilder::silent();
        let result = builder
            .redact_phone_with_strategy("+1-555-123-4567", PhoneRedactionStrategy::ShowLastFour);
        assert!(result.contains("4567"));
    }

    #[test]
    fn test_validate_email() {
        let builder = PersonalBuilder::silent();
        assert!(builder.validate_email("user@example.com").is_ok());
        assert!(builder.validate_email("invalid").is_err());
    }
}
