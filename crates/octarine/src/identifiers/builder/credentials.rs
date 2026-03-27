//! Credentials identifier builder with observability
//!
//! Wraps `primitives::identifiers::CredentialIdentifierBuilder` with observe instrumentation.
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.
//!
//! # Why Wrapper Types?
//!
//! Wrapper types are necessary for two reasons:
//! 1. **Visibility bridging**: Primitives are `pub(crate)`, so we can't directly
//!    re-export them as `pub`. Wrapper types provide the public API surface.
//! 2. **API stability**: Wrappers allow the public API to evolve independently
//!    from internal primitives.

use std::borrow::Cow;
use std::time::Instant;

use crate::observe;
use crate::observe::metrics::{MetricName, increment_by, record};
use crate::primitives::identifiers::{
    CredentialIdentifierBuilder, CredentialMatch, CredentialTextPolicy,
    PassphraseRedactionStrategy, PasswordRedactionStrategy, PinRedactionStrategy,
    SecurityAnswerRedactionStrategy,
};

#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;

    pub fn detect_ms() -> MetricName {
        MetricName::new("data.identifiers.credentials.detect_ms").expect("valid metric name")
    }

    pub fn secrets_found() -> MetricName {
        MetricName::new("data.identifiers.credentials.secrets_found").expect("valid metric name")
    }
}

/// Credentials identifier builder with observability
///
/// Provides detection and sanitization for credentials (passwords, PINs, security answers, passphrases).
///
/// # Example
///
/// ```ignore
/// use octarine::data::identifiers::CredentialsBuilder;
///
/// let builder = CredentialsBuilder::new();
///
/// // Detection
/// if builder.is_passwords_present("password=secret") {
///     println!("Found password pattern");
/// }
///
/// // Silent mode (no events)
/// let silent = CredentialsBuilder::silent();
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct CredentialsBuilder {
    /// The underlying primitive builder
    inner: CredentialIdentifierBuilder,
    /// Whether to emit observe events
    emit_events: bool,
}

impl CredentialsBuilder {
    /// Create a new CredentialsBuilder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: CredentialIdentifierBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: CredentialIdentifierBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // =========================================================================
    // Detection Methods
    // =========================================================================

    /// Check if text contains any credential patterns
    #[must_use]
    pub fn is_credentials_present(&self, text: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_credentials_present(text);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if result {
                increment_by(metric_names::secrets_found(), 1);
                observe::warn("credentials_detected", "Credentials detected in text");
            }
        }

        result
    }

    /// Check if text contains password patterns
    pub fn is_passwords_present(&self, text: &str) -> bool {
        let result = self.inner.is_passwords_present(text);

        if self.emit_events && result {
            observe::debug("password_pattern_detected", "Password pattern detected");
        }

        result
    }

    /// Check if text contains PIN patterns
    pub fn is_pins_present(&self, text: &str) -> bool {
        let result = self.inner.is_pins_present(text);

        if self.emit_events && result {
            observe::debug("pin_pattern_detected", "PIN pattern detected");
        }

        result
    }

    /// Check if text contains security answer patterns
    pub fn is_security_answers_present(&self, text: &str) -> bool {
        let result = self.inner.is_security_answers_present(text);

        if self.emit_events && result {
            observe::debug(
                "security_answer_pattern_detected",
                "Security answer pattern detected",
            );
        }

        result
    }

    /// Check if text contains passphrase patterns
    pub fn is_passphrases_present(&self, text: &str) -> bool {
        let result = self.inner.is_passphrases_present(text);

        if self.emit_events && result {
            observe::debug("passphrase_pattern_detected", "Passphrase pattern detected");
        }

        result
    }

    /// Detect all password matches in text
    #[must_use]
    pub fn detect_passwords(&self, text: &str) -> Vec<CredentialMatch> {
        let matches = self.inner.detect_passwords(text);

        if self.emit_events && !matches.is_empty() {
            increment_by(metric_names::secrets_found(), matches.len() as u64);
            observe::debug(
                "passwords_detected",
                format!("Found {} password(s) in text", matches.len()),
            );
        }

        matches
    }

    /// Detect all PIN matches in text
    #[must_use]
    pub fn detect_pins(&self, text: &str) -> Vec<CredentialMatch> {
        let matches = self.inner.detect_pins(text);

        if self.emit_events && !matches.is_empty() {
            observe::debug(
                "pins_detected",
                format!("Found {} PIN(s) in text", matches.len()),
            );
        }

        matches
    }

    /// Detect all security answer matches in text
    #[must_use]
    pub fn detect_security_answers(&self, text: &str) -> Vec<CredentialMatch> {
        let matches = self.inner.detect_security_answers(text);

        if self.emit_events && !matches.is_empty() {
            observe::debug(
                "security_answers_detected",
                format!("Found {} security answer(s) in text", matches.len()),
            );
        }

        matches
    }

    /// Detect all passphrase matches in text
    #[must_use]
    pub fn detect_passphrases(&self, text: &str) -> Vec<CredentialMatch> {
        let matches = self.inner.detect_passphrases(text);

        if self.emit_events && !matches.is_empty() {
            observe::debug(
                "passphrases_detected",
                format!("Found {} passphrase(s) in text", matches.len()),
            );
        }

        matches
    }

    /// Detect all credential matches in text
    #[must_use]
    pub fn detect_credentials(&self, text: &str) -> Vec<CredentialMatch> {
        let matches = self.inner.detect_credentials(text);

        if self.emit_events && !matches.is_empty() {
            increment_by(metric_names::secrets_found(), matches.len() as u64);
            observe::warn(
                "credentials_in_text",
                format!("Found {} credentials in text", matches.len()),
            );
        }

        matches
    }

    // =========================================================================
    // Connection String Methods
    // =========================================================================

    /// Check if value contains a connection string with embedded credentials
    #[must_use]
    pub fn is_connection_string_with_credentials(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_connection_string_with_credentials(value);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if result {
                increment_by(metric_names::secrets_found(), 1);
                observe::warn(
                    "connection_string_credentials",
                    "Connection string with embedded credentials detected",
                );
            }
        }

        result
    }

    /// Check if value is a database connection string (URL-based)
    #[must_use]
    pub fn is_database_connection_string(&self, value: &str) -> bool {
        self.inner.is_database_connection_string(value)
    }

    /// Find all connection strings with credentials in text
    #[must_use]
    pub fn find_connection_strings_in_text(&self, text: &str) -> Vec<CredentialMatch> {
        let matches = self.inner.find_connection_strings_in_text(text);

        if self.emit_events && !matches.is_empty() {
            increment_by(metric_names::secrets_found(), matches.len() as u64);
            observe::warn(
                "connection_strings_in_text",
                format!(
                    "Found {} connection string(s) with credentials",
                    matches.len()
                ),
            );
        }

        matches
    }

    /// Redact credentials in a connection string while preserving host/database
    #[must_use]
    pub fn redact_connection_string(&self, value: &str) -> String {
        self.inner.redact_connection_string(value)
    }

    /// Redact all connection strings in text
    #[must_use]
    pub fn redact_connection_strings_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let result = self.inner.redact_connection_strings_in_text(text);

        if self.emit_events && result != text {
            observe::info(
                "connection_strings_redacted",
                "Connection string credentials redacted from text",
            );
        }

        result
    }

    // =========================================================================
    // Weak Pattern Detection Methods
    // =========================================================================

    /// Check if password is a known weak/common pattern
    ///
    /// Detects common weak passwords like "password123", "admin", "test".
    /// These should be rejected in production environments.
    #[must_use]
    pub fn is_weak_password(&self, password: &str) -> bool {
        self.inner.is_weak_password(password)
    }

    /// Check if PIN is a known weak/common pattern
    ///
    /// Detects common weak PINs like "0000", "1234", "1111".
    /// These should be rejected in production environments.
    #[must_use]
    pub fn is_weak_pin(&self, pin: &str) -> bool {
        self.inner.is_weak_pin(pin)
    }

    /// Check if security answer is a known weak/placeholder pattern
    ///
    /// Detects placeholder answers like "test", "n/a", "asdf".
    /// These should be rejected in production environments.
    #[must_use]
    pub fn is_weak_security_answer(&self, answer: &str) -> bool {
        self.inner.is_weak_security_answer(answer)
    }

    /// Check if passphrase is a known weak/famous pattern
    ///
    /// Detects famous weak passphrases like "correct horse battery staple".
    /// These should be rejected in production environments.
    #[must_use]
    pub fn is_weak_passphrase(&self, passphrase: &str) -> bool {
        self.inner.is_weak_passphrase(passphrase)
    }

    // =========================================================================
    // Direct Redaction Methods
    // =========================================================================

    /// Redact a password value with explicit strategy
    #[must_use]
    pub fn redact_password_with_strategy(
        &self,
        password: &str,
        strategy: PasswordRedactionStrategy,
    ) -> String {
        self.inner.redact_password_with_strategy(password, strategy)
    }

    /// Redact a PIN value with explicit strategy
    #[must_use]
    pub fn redact_pin_with_strategy(&self, pin: &str, strategy: PinRedactionStrategy) -> String {
        self.inner.redact_pin_with_strategy(pin, strategy)
    }

    /// Redact a security answer value with explicit strategy
    #[must_use]
    pub fn redact_security_answer_with_strategy(
        &self,
        answer: &str,
        strategy: SecurityAnswerRedactionStrategy,
    ) -> String {
        self.inner
            .redact_security_answer_with_strategy(answer, strategy)
    }

    /// Redact a passphrase value with explicit strategy
    #[must_use]
    pub fn redact_passphrase_with_strategy(
        &self,
        passphrase: &str,
        strategy: PassphraseRedactionStrategy,
    ) -> String {
        self.inner
            .redact_passphrase_with_strategy(passphrase, strategy)
    }

    // =========================================================================
    // Text Redaction Methods
    // =========================================================================

    /// Redact all passwords in text with explicit policy
    #[must_use]
    pub fn redact_passwords_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: CredentialTextPolicy,
    ) -> Cow<'a, str> {
        self.inner
            .redact_passwords_in_text_with_policy(text, policy)
    }

    /// Redact all PINs in text with explicit policy
    #[must_use]
    pub fn redact_pins_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: CredentialTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_pins_in_text_with_policy(text, policy)
    }

    /// Redact all credentials in text with explicit policy
    #[must_use]
    pub fn redact_credentials_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: CredentialTextPolicy,
    ) -> Cow<'a, str> {
        let result = self
            .inner
            .redact_credentials_in_text_with_policy(text, policy);

        if self.emit_events && result != text {
            observe::info("credentials_redacted", "Credentials redacted from text");
        }

        result
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = CredentialsBuilder::new();
        assert!(builder.emit_events);

        let silent = CredentialsBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = CredentialsBuilder::new().with_events(false);
        assert!(!builder.emit_events);

        let builder = CredentialsBuilder::silent().with_events(true);
        assert!(builder.emit_events);
    }

    #[test]
    fn test_credentials_detection() {
        let builder = CredentialsBuilder::silent();
        assert!(builder.is_passwords_present("password=secret"));
    }

    #[test]
    fn test_redact_password_with_strategy() {
        let builder = CredentialsBuilder::silent();
        assert_eq!(
            builder.redact_password_with_strategy("hunter2", PasswordRedactionStrategy::Token),
            "[PASSWORD]"
        );
    }

    #[test]
    fn test_is_connection_string_with_credentials() {
        let builder = CredentialsBuilder::silent();
        assert!(
            builder.is_connection_string_with_credentials(
                "postgres://admin:secret@db.example.com/mydb"
            )
        );
        assert!(
            builder.is_connection_string_with_credentials("Server=db.example.com;Password=secret")
        );
        assert!(!builder.is_connection_string_with_credentials("https://example.com"));
    }

    #[test]
    fn test_is_database_connection_string() {
        let builder = CredentialsBuilder::silent();
        assert!(builder.is_database_connection_string("postgres://admin:pw@host/db"));
        assert!(!builder.is_database_connection_string("https://example.com"));
    }

    #[test]
    fn test_redact_connection_string() {
        let builder = CredentialsBuilder::silent();
        let result = builder.redact_connection_string("postgres://admin:secret@host/db");
        assert_eq!(result, "postgres://admin:****@host/db");
    }

    #[test]
    fn test_redact_connection_strings_in_text() {
        let builder = CredentialsBuilder::silent();
        let text = "DB: postgres://admin:secret@host/db";
        let result = builder.redact_connection_strings_in_text(text);
        assert!(!result.contains("secret"));
        assert!(result.contains("****"));
    }

    #[test]
    fn test_is_weak_password() {
        let builder = CredentialsBuilder::silent();
        assert!(builder.is_weak_password("password123"));
        assert!(builder.is_weak_password("admin"));
        assert!(!builder.is_weak_password("x7$kL9mN@pQ2"));
    }

    #[test]
    fn test_is_weak_pin() {
        let builder = CredentialsBuilder::silent();
        assert!(builder.is_weak_pin("1234"));
        assert!(builder.is_weak_pin("0000"));
        assert!(!builder.is_weak_pin("7392"));
    }

    #[test]
    fn test_is_weak_security_answer() {
        let builder = CredentialsBuilder::silent();
        assert!(builder.is_weak_security_answer("test"));
        assert!(builder.is_weak_security_answer("n/a"));
        assert!(!builder.is_weak_security_answer("fluffy"));
    }

    #[test]
    fn test_is_weak_passphrase() {
        let builder = CredentialsBuilder::silent();
        assert!(builder.is_weak_passphrase("correct horse battery staple"));
        assert!(!builder.is_weak_passphrase("purple elephant dancing gracefully"));
    }
}
