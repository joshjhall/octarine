//! Credential sanitization (primitives layer)
//!
//! Pure redaction functions for credentials with NO logging.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Usage Patterns
//!
//! ## Direct Redaction (caller knows the value is a credential)
//!
//! ```ignore
//! let safe = redact_password("hunter2", PasswordRedactionStrategy::Token);
//! // Result: "[PASSWORD]"
//! ```
//!
//! ## Text Scanning (context-based detection)
//!
//! ```ignore
//! let safe = redact_passwords_in_text("password=secret", TextRedactionPolicy::Complete);
//! // Result: "password=[PASSWORD]"
//! ```

use std::borrow::Cow;

use crate::primitives::data::tokens::RedactionTokenCore;

use super::detection::{self, CredentialMatch, CredentialType};
use super::redaction::{
    PassphraseRedactionStrategy, PasswordRedactionStrategy, PinRedactionStrategy,
    SecurityAnswerRedactionStrategy, TextRedactionPolicy,
};

// Individual redaction functions

/// Redact a single password value
///
/// Use this when you know the input is a password. For scanning text
/// to find passwords, use `redact_passwords_in_text()`.
#[must_use]
pub fn redact_password(password: &str, strategy: PasswordRedactionStrategy) -> String {
    match strategy {
        PasswordRedactionStrategy::Skip => password.to_string(),
        PasswordRedactionStrategy::Token => RedactionTokenCore::Password.into(),
        PasswordRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        PasswordRedactionStrategy::Asterisks => "********".to_string(),
        PasswordRedactionStrategy::Hashes => "########".to_string(),
    }
}

/// Redact a single PIN value
#[must_use]
pub fn redact_pin(pin: &str, strategy: PinRedactionStrategy) -> String {
    match strategy {
        PinRedactionStrategy::Skip => pin.to_string(),
        PinRedactionStrategy::Token => RedactionTokenCore::Pin.into(),
        PinRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        PinRedactionStrategy::Asterisks => "****".to_string(),
        PinRedactionStrategy::ShowLength => format!("[PIN:{}]", pin.len()),
    }
}

/// Redact a single security answer value
#[must_use]
pub fn redact_security_answer(answer: &str, strategy: SecurityAnswerRedactionStrategy) -> String {
    match strategy {
        SecurityAnswerRedactionStrategy::Skip => answer.to_string(),
        SecurityAnswerRedactionStrategy::Token => RedactionTokenCore::SecurityAnswer.into(),
        SecurityAnswerRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        SecurityAnswerRedactionStrategy::Asterisks => "********".to_string(),
    }
}

/// Redact a single passphrase value
#[must_use]
pub fn redact_passphrase(passphrase: &str, strategy: PassphraseRedactionStrategy) -> String {
    match strategy {
        PassphraseRedactionStrategy::Skip => passphrase.to_string(),
        PassphraseRedactionStrategy::Token => RedactionTokenCore::Passphrase.into(),
        PassphraseRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        PassphraseRedactionStrategy::Asterisks => "********".to_string(),
        PassphraseRedactionStrategy::ShowWordCount => {
            let word_count = passphrase.split_whitespace().count();
            format!("[PASSPHRASE:{} words]", word_count)
        }
    }
}

// Text redaction functions (context-based detection)

/// Redact all passwords in text
///
/// Uses context-based detection to find password patterns and redact them.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::credentials::{
///     redact_passwords_in_text, TextRedactionPolicy
/// };
///
/// let text = "password=secret123";
/// let safe = redact_passwords_in_text(text, TextRedactionPolicy::Complete);
/// assert_eq!(safe, "password=[PASSWORD]");
/// ```
#[must_use]
pub fn redact_passwords_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_password_strategy();
    if matches!(strategy, PasswordRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let matches = detection::detect_passwords(text);
    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();

    // Replace from end to start to preserve positions
    for m in matches.iter().rev() {
        let redacted = redact_password(&m.value, strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

/// Redact all PINs in text
#[must_use]
pub fn redact_pins_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_pin_strategy();
    if matches!(strategy, PinRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let matches = detection::detect_pins(text);
    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();

    for m in matches.iter().rev() {
        let redacted = redact_pin(&m.value, strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

/// Redact all credentials (passwords, PINs, etc.) in text
#[must_use]
pub fn redact_credentials_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let matches = detection::detect_credentials(text);
    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();

    // Replace from end to start to preserve positions
    for m in matches.iter().rev() {
        let redacted = redact_credential_match(m, policy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

/// Redact a credential match based on its type
fn redact_credential_match(m: &CredentialMatch, policy: TextRedactionPolicy) -> String {
    match m.credential_type {
        CredentialType::Password => redact_password(&m.value, policy.to_password_strategy()),
        CredentialType::Pin => redact_pin(&m.value, policy.to_pin_strategy()),
        CredentialType::SecurityAnswer => {
            redact_security_answer(&m.value, policy.to_security_answer_strategy())
        }
        CredentialType::Passphrase => redact_passphrase(&m.value, policy.to_passphrase_strategy()),
        CredentialType::Generic => {
            // Use password token as default for unknown credentials
            redact_password(&m.value, policy.to_password_strategy())
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Individual redaction tests

    #[test]
    fn test_redact_password_token() {
        assert_eq!(
            redact_password("hunter2", PasswordRedactionStrategy::Token),
            "[PASSWORD]"
        );
    }

    #[test]
    fn test_redact_password_anonymous() {
        assert_eq!(
            redact_password("hunter2", PasswordRedactionStrategy::Anonymous),
            "[REDACTED]"
        );
    }

    #[test]
    fn test_redact_password_asterisks() {
        assert_eq!(
            redact_password("hunter2", PasswordRedactionStrategy::Asterisks),
            "********"
        );
    }

    #[test]
    fn test_redact_password_none() {
        assert_eq!(
            redact_password("hunter2", PasswordRedactionStrategy::Skip),
            "hunter2"
        );
    }

    #[test]
    fn test_redact_pin_token() {
        assert_eq!(redact_pin("1234", PinRedactionStrategy::Token), "[PIN]");
    }

    #[test]
    fn test_redact_pin_show_length() {
        assert_eq!(
            redact_pin("1234", PinRedactionStrategy::ShowLength),
            "[PIN:4]"
        );
        assert_eq!(
            redact_pin("123456", PinRedactionStrategy::ShowLength),
            "[PIN:6]"
        );
    }

    #[test]
    fn test_redact_passphrase_word_count() {
        assert_eq!(
            redact_passphrase(
                "correct horse battery staple",
                PassphraseRedactionStrategy::ShowWordCount
            ),
            "[PASSPHRASE:4 words]"
        );
    }

    // Text redaction tests

    #[test]
    fn test_redact_passwords_in_text_basic() {
        let text = "password=secret123";
        let result = redact_passwords_in_text(text, TextRedactionPolicy::Complete);
        assert_eq!(result, "password=[PASSWORD]");
    }

    #[test]
    fn test_redact_passwords_in_text_colon() {
        let text = "password: secret123";
        let result = redact_passwords_in_text(text, TextRedactionPolicy::Complete);
        assert_eq!(result, "password: [PASSWORD]");
    }

    #[test]
    fn test_redact_passwords_in_text_json() {
        let text = r#"{"password": "hunter2"}"#;
        let result = redact_passwords_in_text(text, TextRedactionPolicy::Complete);
        assert_eq!(result, r#"{"password": "[PASSWORD]"}"#);
    }

    #[test]
    fn test_redact_passwords_in_text_multiple() {
        let text = "password=secret1 and pwd=secret2";
        let result = redact_passwords_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[PASSWORD]"));
        assert!(!result.contains("secret1"));
        assert!(!result.contains("secret2"));
    }

    #[test]
    fn test_redact_passwords_no_match() {
        let text = "no credentials here";
        let result = redact_passwords_in_text(text, TextRedactionPolicy::Complete);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_passwords_none_policy() {
        let text = "password=secret123";
        let result = redact_passwords_in_text(text, TextRedactionPolicy::Skip);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_pins_in_text() {
        let text = "pin=1234";
        let result = redact_pins_in_text(text, TextRedactionPolicy::Complete);
        assert_eq!(result, "pin=[PIN]");
    }

    #[test]
    fn test_redact_credentials_mixed() {
        let text = r#"{"password": "secret", "pin": "1234"}"#;
        let result = redact_credentials_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[PASSWORD]"));
        assert!(result.contains("[PIN]"));
        assert!(!result.contains("secret"));
        assert!(!result.contains("1234"));
    }
}
