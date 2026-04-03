//! Credential identifier builder
//!
//! Unified builder API for credential identifier operations.

use std::borrow::Cow;

use super::{detection, redaction, sanitization, validation};

/// Builder for credential identifier operations
///
/// Provides a unified interface for detection and sanitization
/// of knowledge-based authentication secrets (NIST Factor 1).
///
/// # Example
///
/// ```ignore
/// use octarine::primitives::identifiers::credentials::CredentialIdentifierBuilder;
///
/// let builder = CredentialIdentifierBuilder::new();
///
/// // Direct redaction
/// let safe = builder.redact_password("hunter2");
/// assert_eq!(safe, "[PASSWORD]");
///
/// // Context-based text redaction
/// let text = "password=secret123";
/// let safe = builder.redact_passwords_in_text(text);
/// assert_eq!(safe, "password=[PASSWORD]");
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct CredentialIdentifierBuilder;

impl CredentialIdentifierBuilder {
    /// Create a new credential identifier builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // Detection methods

    /// Check if text contains any credential patterns
    #[must_use]
    pub fn is_credentials_present(&self, text: &str) -> bool {
        detection::is_credentials_present(text)
    }

    /// Check if text contains password patterns
    #[must_use]
    pub fn is_passwords_present(&self, text: &str) -> bool {
        detection::is_passwords_present(text)
    }

    /// Check if text contains PIN patterns
    #[must_use]
    pub fn is_pins_present(&self, text: &str) -> bool {
        detection::is_pins_present(text)
    }

    /// Check if text contains security answer patterns
    #[must_use]
    pub fn is_security_answers_present(&self, text: &str) -> bool {
        detection::is_security_answers_present(text)
    }

    /// Check if text contains passphrase patterns
    #[must_use]
    pub fn is_passphrases_present(&self, text: &str) -> bool {
        detection::is_passphrases_present(text)
    }

    /// Detect all password matches in text
    #[must_use]
    pub fn detect_passwords(&self, text: &str) -> Vec<detection::CredentialMatch> {
        detection::detect_passwords(text)
    }

    /// Detect all PIN matches in text
    #[must_use]
    pub fn detect_pins(&self, text: &str) -> Vec<detection::CredentialMatch> {
        detection::detect_pins(text)
    }

    /// Detect all security answer matches in text
    #[must_use]
    pub fn detect_security_answers(&self, text: &str) -> Vec<detection::CredentialMatch> {
        detection::detect_security_answers(text)
    }

    /// Detect all passphrase matches in text
    #[must_use]
    pub fn detect_passphrases(&self, text: &str) -> Vec<detection::CredentialMatch> {
        detection::detect_passphrases(text)
    }

    /// Detect all credential matches in text
    #[must_use]
    pub fn detect_credentials(&self, text: &str) -> Vec<detection::CredentialMatch> {
        detection::detect_credentials(text)
    }

    // Connection string detection methods

    /// Check if value contains a connection string with embedded credentials
    #[must_use]
    pub fn is_connection_string_with_credentials(&self, value: &str) -> bool {
        detection::is_connection_string_with_credentials(value)
    }

    /// Check if value is a database connection string (URL-based)
    #[must_use]
    pub fn is_database_connection_string(&self, value: &str) -> bool {
        detection::is_database_connection_string(value)
    }

    /// Find all connection strings with credentials in text
    #[must_use]
    pub fn find_connection_strings_in_text(&self, text: &str) -> Vec<detection::CredentialMatch> {
        detection::find_connection_strings_in_text(text)
    }

    /// Redact credentials in a connection string while preserving host/database
    #[must_use]
    pub fn redact_connection_string(&self, value: &str) -> String {
        sanitization::redact_connection_string(value)
    }

    /// Redact all connection strings in text
    #[must_use]
    pub fn redact_connection_strings_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        sanitization::redact_connection_strings_in_text(text)
    }

    // Validation methods

    /// Validate a connection string with embedded credentials
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the connection string format is invalid
    pub fn validate_connection_string(
        &self,
        value: &str,
    ) -> Result<(), crate::primitives::Problem> {
        validation::validate_connection_string(value)
    }

    /// Validate a database connection string format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the database connection string format is invalid
    pub fn validate_database_connection_string(
        &self,
        value: &str,
    ) -> Result<(), crate::primitives::Problem> {
        validation::validate_database_connection_string(value)
    }

    // Weak pattern detection methods

    /// Check if password is a known weak/common pattern
    ///
    /// Detects common weak passwords like "password123", "admin", "test".
    /// These should be rejected in production environments.
    #[must_use]
    pub fn is_weak_password(&self, password: &str) -> bool {
        detection::is_weak_password(password)
    }

    /// Check if PIN is a known weak/common pattern
    ///
    /// Detects common weak PINs like "0000", "1234", "1111".
    /// These should be rejected in production environments.
    #[must_use]
    pub fn is_weak_pin(&self, pin: &str) -> bool {
        detection::is_weak_pin(pin)
    }

    /// Check if security answer is a known weak/placeholder pattern
    ///
    /// Detects placeholder answers like "test", "n/a", "asdf".
    /// These should be rejected in production environments.
    #[must_use]
    pub fn is_weak_security_answer(&self, answer: &str) -> bool {
        detection::is_weak_security_answer(answer)
    }

    /// Check if passphrase is a known weak/famous pattern
    ///
    /// Detects famous weak passphrases like "correct horse battery staple".
    /// These should be rejected in production environments.
    #[must_use]
    pub fn is_weak_passphrase(&self, passphrase: &str) -> bool {
        detection::is_weak_passphrase(passphrase)
    }

    // Direct redaction methods (caller knows it's a credential)

    /// Redact a password value with explicit strategy
    #[must_use]
    pub fn redact_password_with_strategy(
        &self,
        password: &str,
        strategy: redaction::PasswordRedactionStrategy,
    ) -> String {
        sanitization::redact_password(password, strategy)
    }

    /// Redact a PIN value with explicit strategy
    #[must_use]
    pub fn redact_pin_with_strategy(
        &self,
        pin: &str,
        strategy: redaction::PinRedactionStrategy,
    ) -> String {
        sanitization::redact_pin(pin, strategy)
    }

    /// Redact a security answer value with explicit strategy
    #[must_use]
    pub fn redact_security_answer_with_strategy(
        &self,
        answer: &str,
        strategy: redaction::SecurityAnswerRedactionStrategy,
    ) -> String {
        sanitization::redact_security_answer(answer, strategy)
    }

    /// Redact a passphrase value with explicit strategy
    #[must_use]
    pub fn redact_passphrase_with_strategy(
        &self,
        passphrase: &str,
        strategy: redaction::PassphraseRedactionStrategy,
    ) -> String {
        sanitization::redact_passphrase(passphrase, strategy)
    }

    // Text redaction methods (context-based detection)

    /// Redact all passwords in text with explicit policy
    #[must_use]
    pub fn redact_passwords_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: redaction::TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_passwords_in_text(text, policy)
    }

    /// Redact all PINs in text with explicit policy
    #[must_use]
    pub fn redact_pins_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: redaction::TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_pins_in_text(text, policy)
    }

    /// Redact all credentials in text with explicit policy
    #[must_use]
    pub fn redact_credentials_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: redaction::TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_credentials_in_text(text, policy)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Builder creation tests

    #[test]
    fn test_builder_creation() {
        let builder = CredentialIdentifierBuilder::new();
        assert!(builder.is_passwords_present("password=secret"));
    }

    #[test]
    fn test_builder_default() {
        let builder: CredentialIdentifierBuilder = Default::default();
        assert!(builder.is_passwords_present("password=secret"));
    }

    // Detection tests

    #[test]
    fn test_is_passwords_present() {
        let builder = CredentialIdentifierBuilder::new();
        assert!(builder.is_passwords_present("password=secret"));
        assert!(builder.is_passwords_present("pwd: hunter2"));
        assert!(builder.is_passwords_present(r#"{"password": "value"}"#));
        assert!(!builder.is_passwords_present("no credentials"));
    }

    #[test]
    fn test_is_pins_present() {
        let builder = CredentialIdentifierBuilder::new();
        assert!(builder.is_pins_present("pin=1234"));
        assert!(builder.is_pins_present("PIN: 5678"));
        assert!(builder.is_pins_present(r#"{"pin": "9012"}"#));
        assert!(!builder.is_pins_present("no pins here"));
    }

    #[test]
    fn test_is_credentials_present() {
        let builder = CredentialIdentifierBuilder::new();
        assert!(builder.is_credentials_present("password=secret"));
        assert!(builder.is_credentials_present("pin=1234"));
        assert!(!builder.is_credentials_present("no credentials"));
    }

    #[test]
    fn test_detect_passwords() {
        let builder = CredentialIdentifierBuilder::new();
        let matches = builder.detect_passwords("password=secret123");
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("should have one match");
        assert_eq!(first.value, "secret123");
        assert_eq!(first.label, "password");
    }

    #[test]
    fn test_detect_pins() {
        let builder = CredentialIdentifierBuilder::new();
        let matches = builder.detect_pins("pin=1234");
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("should have one match");
        assert_eq!(first.value, "1234");
    }

    #[test]
    fn test_detect_credentials() {
        let builder = CredentialIdentifierBuilder::new();
        let text = r#"{"password": "secret", "pin": "1234"}"#;
        let matches = builder.detect_credentials(text);
        assert_eq!(matches.len(), 2);
    }

    // Direct redaction tests

    #[test]
    fn test_redact_password_with_strategy() {
        let builder = CredentialIdentifierBuilder::new();
        assert_eq!(
            builder.redact_password_with_strategy(
                "hunter2",
                redaction::PasswordRedactionStrategy::Token
            ),
            "[PASSWORD]"
        );
        assert_eq!(
            builder.redact_password_with_strategy(
                "hunter2",
                redaction::PasswordRedactionStrategy::Asterisks
            ),
            "********"
        );
        assert_eq!(
            builder.redact_password_with_strategy(
                "hunter2",
                redaction::PasswordRedactionStrategy::Anonymous
            ),
            "[REDACTED]"
        );
    }

    #[test]
    fn test_redact_pin_with_strategy() {
        let builder = CredentialIdentifierBuilder::new();
        assert_eq!(
            builder.redact_pin_with_strategy("1234", redaction::PinRedactionStrategy::Token),
            "[PIN]"
        );
        assert_eq!(
            builder.redact_pin_with_strategy("1234", redaction::PinRedactionStrategy::ShowLength),
            "[PIN:4]"
        );
    }

    #[test]
    fn test_redact_security_answer_with_strategy() {
        let builder = CredentialIdentifierBuilder::new();
        assert_eq!(
            builder.redact_security_answer_with_strategy(
                "fluffy",
                redaction::SecurityAnswerRedactionStrategy::Token
            ),
            "[SECURITY_ANSWER]"
        );
    }

    #[test]
    fn test_redact_passphrase_with_strategy() {
        let builder = CredentialIdentifierBuilder::new();
        assert_eq!(
            builder.redact_passphrase_with_strategy(
                "correct horse battery staple",
                redaction::PassphraseRedactionStrategy::Token
            ),
            "[PASSPHRASE]"
        );
        assert_eq!(
            builder.redact_passphrase_with_strategy(
                "correct horse battery staple",
                redaction::PassphraseRedactionStrategy::ShowWordCount
            ),
            "[PASSPHRASE:4 words]"
        );
    }

    // Text redaction tests

    #[test]
    fn test_redact_passwords_in_text_with_policy() {
        let builder = CredentialIdentifierBuilder::new();
        let result = builder.redact_passwords_in_text_with_policy(
            "password=secret123",
            redaction::TextRedactionPolicy::Complete,
        );
        assert_eq!(result, "password=[PASSWORD]");

        let result = builder.redact_passwords_in_text_with_policy(
            "password=secret123",
            redaction::TextRedactionPolicy::Partial,
        );
        assert_eq!(result, "password=********");
    }

    #[test]
    fn test_redact_pins_in_text_with_policy() {
        let builder = CredentialIdentifierBuilder::new();
        let result = builder
            .redact_pins_in_text_with_policy("pin=1234", redaction::TextRedactionPolicy::Complete);
        assert_eq!(result, "pin=[PIN]");

        let result = builder
            .redact_pins_in_text_with_policy("pin=1234", redaction::TextRedactionPolicy::Partial);
        assert_eq!(result, "pin=[PIN:4]");
    }

    #[test]
    fn test_redact_credentials_in_text_with_policy() {
        let builder = CredentialIdentifierBuilder::new();
        let text = r#"{"password": "secret", "pin": "1234"}"#;

        let result = builder
            .redact_credentials_in_text_with_policy(text, redaction::TextRedactionPolicy::Complete);
        assert!(result.contains("[PASSWORD]"));
        assert!(result.contains("[PIN]"));

        let result = builder.redact_credentials_in_text_with_policy(
            text,
            redaction::TextRedactionPolicy::Anonymous,
        );
        // Both should be [REDACTED] with anonymous policy
        assert!(result.contains("[REDACTED]"));
        assert!(!result.contains("[PASSWORD]"));
        assert!(!result.contains("[PIN]"));
    }

    // No match tests (Cow::Borrowed optimization)

    #[test]
    fn test_no_credentials_returns_borrowed() {
        let builder = CredentialIdentifierBuilder::new();
        let text = "no credentials here";
        let result = builder
            .redact_passwords_in_text_with_policy(text, redaction::TextRedactionPolicy::Complete);
        // When no matches, should return Borrowed (same pointer)
        assert_eq!(result, text);
    }

    // Connection string tests

    #[test]
    fn test_is_connection_string_with_credentials() {
        let builder = CredentialIdentifierBuilder::new();
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
        let builder = CredentialIdentifierBuilder::new();
        assert!(builder.is_database_connection_string("postgres://admin:pw@host/db"));
        assert!(builder.is_database_connection_string("mysql://root:pw@host/db"));
        assert!(!builder.is_database_connection_string("https://example.com"));
    }

    #[test]
    fn test_redact_connection_string() {
        let builder = CredentialIdentifierBuilder::new();
        let result = builder.redact_connection_string("postgres://admin:secret@host/db");
        assert_eq!(result, "postgres://admin:****@host/db");
    }

    #[test]
    fn test_redact_connection_strings_in_text() {
        let builder = CredentialIdentifierBuilder::new();
        let text = "DB: postgres://admin:secret@host/db";
        let result = builder.redact_connection_strings_in_text(text);
        assert!(!result.contains("secret"));
        assert!(result.contains("****"));
    }

    // Weak pattern detection tests

    #[test]
    fn test_is_weak_password() {
        let builder = CredentialIdentifierBuilder::new();
        assert!(builder.is_weak_password("password123"));
        assert!(builder.is_weak_password("admin"));
        assert!(builder.is_weak_password("hunter2"));
        assert!(!builder.is_weak_password("x7$kL9mN@pQ2"));
    }

    #[test]
    fn test_is_weak_pin() {
        let builder = CredentialIdentifierBuilder::new();
        assert!(builder.is_weak_pin("1234"));
        assert!(builder.is_weak_pin("0000"));
        assert!(!builder.is_weak_pin("7392"));
    }

    #[test]
    fn test_is_weak_security_answer() {
        let builder = CredentialIdentifierBuilder::new();
        assert!(builder.is_weak_security_answer("test"));
        assert!(builder.is_weak_security_answer("n/a"));
        assert!(!builder.is_weak_security_answer("fluffy"));
    }

    #[test]
    fn test_is_weak_passphrase() {
        let builder = CredentialIdentifierBuilder::new();
        assert!(builder.is_weak_passphrase("correct horse battery staple"));
        assert!(!builder.is_weak_passphrase("purple elephant dancing gracefully"));
    }

    // Validation tests

    #[test]
    fn test_validate_connection_string() {
        let builder = CredentialIdentifierBuilder::new();

        assert!(
            builder
                .validate_connection_string(
                    "postgres://admin:strongP@ss99@db.example.com:5432/mydb"
                )
                .is_ok()
        );
        assert!(
            builder
                .validate_connection_string(
                    "Server=db.example.com;Database=mydb;Password=Str0ngP@ss"
                )
                .is_ok()
        );
        assert!(builder.validate_connection_string("").is_err());
        assert!(
            builder
                .validate_connection_string("not-a-connection-string")
                .is_err()
        );
    }

    #[test]
    fn test_validate_database_connection_string() {
        let builder = CredentialIdentifierBuilder::new();

        assert!(
            builder
                .validate_database_connection_string("postgres://host:5432/db")
                .is_ok()
        );
        assert!(
            builder
                .validate_database_connection_string("redis://localhost:6379")
                .is_ok()
        );
        assert!(builder.validate_database_connection_string("").is_err());
        assert!(
            builder
                .validate_database_connection_string("http://example.com")
                .is_err()
        );
    }
}
