//! Credential detection (primitives layer)
//!
//! Context-based detection for credentials in text. Unlike pattern-based detection
//! (SSN, credit card), credentials are opaque strings detected by their context.
//!
//! # Detection Strategies
//!
//! 1. **Label-based**: `password:`, `pin=`, `secret:`
//! 2. **JSON keys**: `"password": "value"`, `"pin": "1234"`
//! 3. **YAML keys**: `password: value`
//! 4. **URL parameters**: `?password=value&`
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns match positions and types

use super::super::common::patterns::credentials::{passphrase, password, pin, security_answer};

// Re-export types from shared types module
pub use super::super::types::{CredentialMatch, CredentialType};

// Detection functions

/// Check if text contains any credential patterns
///
/// Quick check without extracting matches.
#[must_use]
pub fn is_credentials_present(text: &str) -> bool {
    let lower = text.to_lowercase();

    // Quick keyword check first
    if !lower.contains("password")
        && !lower.contains("passwd")
        && !lower.contains("pwd")
        && !lower.contains("secret")
        && !lower.contains("pin")
        && !lower.contains("passphrase")
        && !lower.contains("credential")
    {
        return false;
    }

    // Check for assignment patterns
    password::FIELD.is_match(text)
        || pin::FIELD.is_match(text)
        || security_answer::FIELD.is_match(text)
        || passphrase::FIELD.is_match(text)
        || password::JSON.is_match(text)
        || pin::JSON.is_match(text)
}

/// Check if text contains password patterns
#[must_use]
pub fn is_passwords_present(text: &str) -> bool {
    let lower = text.to_lowercase();
    if !lower.contains("password")
        && !lower.contains("passwd")
        && !lower.contains("pwd")
        && !lower.contains("pass")
        && !lower.contains("secret")
        && !lower.contains("credential")
    {
        return false;
    }

    password::FIELD.is_match(text) || password::JSON.is_match(text)
}

/// Check if text contains PIN patterns
#[must_use]
pub fn is_pins_present(text: &str) -> bool {
    let lower = text.to_lowercase();
    if !lower.contains("pin") && !lower.contains("security_code") {
        return false;
    }

    pin::FIELD.is_match(text) || pin::JSON.is_match(text)
}

/// Check if text contains security answer patterns
#[must_use]
pub fn is_security_answers_present(text: &str) -> bool {
    let lower = text.to_lowercase();
    if !lower.contains("security_answer")
        && !lower.contains("secret_answer")
        && !lower.contains("security_question")
    {
        return false;
    }

    security_answer::FIELD.is_match(text) || security_answer::JSON.is_match(text)
}

/// Check if text contains passphrase patterns
#[must_use]
pub fn is_passphrases_present(text: &str) -> bool {
    let lower = text.to_lowercase();
    if !lower.contains("passphrase") && !lower.contains("pass_phrase") {
        return false;
    }

    passphrase::FIELD.is_match(text) || passphrase::JSON.is_match(text)
}

/// Detect all password matches in text
#[must_use]
pub fn detect_passwords(text: &str) -> Vec<CredentialMatch> {
    let mut matches = Vec::new();

    // Check field patterns (password=value, password: value)
    for cap in password::FIELD.captures_iter(text) {
        if let (Some(label_match), Some(value_match)) = (cap.get(1), cap.get(2)) {
            matches.push(CredentialMatch {
                start: value_match.start(),
                end: value_match.end(),
                value: value_match.as_str().to_string(),
                credential_type: CredentialType::Password,
                label: label_match.as_str().to_string(),
            });
        }
    }

    // Check JSON patterns ("password": "value")
    for cap in password::JSON.captures_iter(text) {
        if let (Some(label_match), Some(value_match)) = (cap.get(1), cap.get(2)) {
            // Avoid duplicates if same position already matched
            let start = value_match.start();
            if !matches.iter().any(|m| m.start == start) {
                matches.push(CredentialMatch {
                    start,
                    end: value_match.end(),
                    value: value_match.as_str().to_string(),
                    credential_type: CredentialType::Password,
                    label: label_match.as_str().to_string(),
                });
            }
        }
    }

    // Sort by position (for consistent replacement order)
    matches.sort_by_key(|m| m.start);
    matches
}

/// Detect all PIN matches in text
#[must_use]
pub fn detect_pins(text: &str) -> Vec<CredentialMatch> {
    let mut matches = Vec::new();

    for cap in pin::FIELD.captures_iter(text) {
        if let (Some(label_match), Some(value_match)) = (cap.get(1), cap.get(2)) {
            matches.push(CredentialMatch {
                start: value_match.start(),
                end: value_match.end(),
                value: value_match.as_str().to_string(),
                credential_type: CredentialType::Pin,
                label: label_match.as_str().to_string(),
            });
        }
    }

    for cap in pin::JSON.captures_iter(text) {
        if let (Some(label_match), Some(value_match)) = (cap.get(1), cap.get(2)) {
            let start = value_match.start();
            if !matches.iter().any(|m| m.start == start) {
                matches.push(CredentialMatch {
                    start,
                    end: value_match.end(),
                    value: value_match.as_str().to_string(),
                    credential_type: CredentialType::Pin,
                    label: label_match.as_str().to_string(),
                });
            }
        }
    }

    matches.sort_by_key(|m| m.start);
    matches
}

/// Detect all security answer matches in text
#[must_use]
pub fn detect_security_answers(text: &str) -> Vec<CredentialMatch> {
    let mut matches = Vec::new();

    for cap in security_answer::FIELD.captures_iter(text) {
        if let (Some(label_match), Some(value_match)) = (cap.get(1), cap.get(2)) {
            matches.push(CredentialMatch {
                start: value_match.start(),
                end: value_match.end(),
                value: value_match.as_str().to_string(),
                credential_type: CredentialType::SecurityAnswer,
                label: label_match.as_str().to_string(),
            });
        }
    }

    for cap in security_answer::JSON.captures_iter(text) {
        if let (Some(label_match), Some(value_match)) = (cap.get(1), cap.get(2)) {
            let start = value_match.start();
            if !matches.iter().any(|m| m.start == start) {
                matches.push(CredentialMatch {
                    start,
                    end: value_match.end(),
                    value: value_match.as_str().to_string(),
                    credential_type: CredentialType::SecurityAnswer,
                    label: label_match.as_str().to_string(),
                });
            }
        }
    }

    matches.sort_by_key(|m| m.start);
    matches
}

/// Detect all passphrase matches in text
#[must_use]
pub fn detect_passphrases(text: &str) -> Vec<CredentialMatch> {
    let mut matches = Vec::new();

    for cap in passphrase::FIELD.captures_iter(text) {
        if let (Some(label_match), Some(value_match)) = (cap.get(1), cap.get(2)) {
            matches.push(CredentialMatch {
                start: value_match.start(),
                end: value_match.end(),
                value: value_match.as_str().trim().to_string(),
                credential_type: CredentialType::Passphrase,
                label: label_match.as_str().to_string(),
            });
        }
    }

    for cap in passphrase::JSON.captures_iter(text) {
        if let (Some(label_match), Some(value_match)) = (cap.get(1), cap.get(2)) {
            let start = value_match.start();
            if !matches.iter().any(|m| m.start == start) {
                matches.push(CredentialMatch {
                    start,
                    end: value_match.end(),
                    value: value_match.as_str().to_string(),
                    credential_type: CredentialType::Passphrase,
                    label: label_match.as_str().to_string(),
                });
            }
        }
    }

    matches.sort_by_key(|m| m.start);
    matches
}

/// Detect all credential matches in text (passwords, PINs, security answers, passphrases)
#[must_use]
pub fn detect_credentials(text: &str) -> Vec<CredentialMatch> {
    let mut matches = Vec::new();

    matches.extend(detect_passwords(text));
    matches.extend(detect_pins(text));
    matches.extend(detect_security_answers(text));
    matches.extend(detect_passphrases(text));

    // Sort by position
    matches.sort_by_key(|m| m.start);
    matches
}

// ============================================================================
// Weak Pattern Detection
// ============================================================================

/// Common weak/dummy password patterns
const WEAK_PASSWORDS: &[&str] = &[
    "password",
    "password1",
    "password123",
    "test",
    "test123",
    "admin",
    "admin123",
    "secret",
    "secret123",
    "hunter2",
    "letmein",
    "welcome",
    "welcome1",
    "changeme",
    "qwerty",
    "qwerty123",
    "abc123",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "pass",
    "pass123",
    "demo",
    "demo123",
    "sample",
    "example",
    "default",
    "temp",
    "temp123",
    "guest",
    "guest123",
    "root",
    "root123",
    "user",
    "user123",
    "pa$$word",
    "p@ssword",
    "p@ssw0rd",
];

/// Check if password is a known weak/dummy pattern
///
/// Detects common weak passwords used in testing, demos, and examples.
/// These should be rejected in production environments.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::credentials::detection::is_weak_password;
///
/// assert!(is_weak_password("password123"));
/// assert!(is_weak_password("hunter2"));
/// assert!(!is_weak_password("x7$kL9mN@pQ2"));
/// ```
#[must_use]
pub fn is_weak_password(password: &str) -> bool {
    let lower = password.to_lowercase();
    WEAK_PASSWORDS.iter().any(|&p| lower == p)
}

/// Common weak/dummy PIN patterns
const WEAK_PINS: &[&str] = &[
    "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999", "1234", "4321",
    "1212", "2121", "0123", "3210", "1357", "2468", "9876", "6789", "0101", "1010", "12345",
    "123456", "54321", "654321",
];

/// Check if PIN is a known weak/dummy pattern
///
/// Detects common weak PINs like sequential, repeated, or pattern digits.
/// These should be rejected in production environments.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::credentials::detection::is_weak_pin;
///
/// assert!(is_weak_pin("1234"));
/// assert!(is_weak_pin("0000"));
/// assert!(!is_weak_pin("7392"));
/// ```
#[must_use]
pub fn is_weak_pin(pin: &str) -> bool {
    WEAK_PINS.contains(&pin)
}

/// Common weak/dummy security answer patterns
const WEAK_SECURITY_ANSWERS: &[&str] = &[
    "test",
    "none",
    "n/a",
    "na",
    "null",
    "empty",
    "unknown",
    "default",
    "answer",
    "secret",
    "xxx",
    "aaa",
    "asdf",
    "qwerty",
    "123",
    "1234",
    "abc",
    "placeholder",
    "sample",
    "example",
    "demo",
    "temp",
    "dummy",
];

/// Check if security answer is a known weak/dummy pattern
///
/// Detects common placeholder security answers used in testing.
/// These should be rejected in production environments.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::credentials::detection::is_weak_security_answer;
///
/// assert!(is_weak_security_answer("test"));
/// assert!(is_weak_security_answer("n/a"));
/// assert!(!is_weak_security_answer("my first pet was fluffy"));
/// ```
#[must_use]
pub fn is_weak_security_answer(answer: &str) -> bool {
    let lower = answer.to_lowercase().trim().to_string();
    WEAK_SECURITY_ANSWERS.iter().any(|&a| lower == a)
}

/// Check if passphrase is a known weak/dummy pattern
///
/// Detects common weak passphrases like "correct horse battery staple"
/// and other famous examples.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::credentials::detection::is_weak_passphrase;
///
/// assert!(is_weak_passphrase("correct horse battery staple"));
/// assert!(!is_weak_passphrase("random words chosen wisely"));
/// ```
#[must_use]
pub fn is_weak_passphrase(passphrase: &str) -> bool {
    let lower = passphrase.to_lowercase();

    // Famous weak passphrases
    let weak_passphrases = [
        "correct horse battery staple", // xkcd
        "test passphrase",
        "test test test",
        "sample passphrase",
        "example passphrase",
        "demo passphrase",
        "default passphrase",
        "the quick brown fox",
        "lorem ipsum",
        "password password password",
    ];

    weak_passphrases.iter().any(|&p| lower.contains(p))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_passwords_present() {
        assert!(is_passwords_present("password=secret123"));
        assert!(is_passwords_present("password: secret123"));
        assert!(is_passwords_present("PASSWORD = hunter2"));
        assert!(is_passwords_present(r#""password": "secret""#));
        assert!(!is_passwords_present("no credentials here"));
        assert!(!is_passwords_present("the word password alone"));
    }

    #[test]
    fn test_is_pins_present() {
        assert!(is_pins_present("pin=1234"));
        assert!(is_pins_present("PIN: 5678"));
        assert!(is_pins_present(r#""pin": "9012""#));
        assert!(!is_pins_present("no pin here"));
        assert!(!is_pins_present("pin without value"));
    }

    #[test]
    fn test_detect_passwords_basic() {
        let matches = detect_passwords("password=secret123");
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("should have one match");
        assert_eq!(first.value, "secret123");
        assert_eq!(first.credential_type, CredentialType::Password);
    }

    #[test]
    fn test_detect_passwords_json() {
        let matches = detect_passwords(r#"{"password": "hunter2"}"#);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("should have one match");
        assert_eq!(first.value, "hunter2");
    }

    #[test]
    fn test_detect_passwords_multiple() {
        let text = "password=secret1 and pwd=secret2";
        let matches = detect_passwords(text);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_detect_pins() {
        let matches = detect_pins("pin=1234");
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("should have one match");
        assert_eq!(first.value, "1234");
        assert_eq!(first.credential_type, CredentialType::Pin);
    }

    #[test]
    fn test_detect_credentials_mixed() {
        let text = r#"{"password": "secret", "pin": "1234"}"#;
        let matches = detect_credentials(text);
        assert_eq!(matches.len(), 2);

        let passwords: Vec<_> = matches
            .iter()
            .filter(|m| m.credential_type == CredentialType::Password)
            .collect();
        let pins: Vec<_> = matches
            .iter()
            .filter(|m| m.credential_type == CredentialType::Pin)
            .collect();

        assert_eq!(passwords.len(), 1);
        assert_eq!(pins.len(), 1);
    }

    #[test]
    fn test_credential_type_name() {
        assert_eq!(CredentialType::Password.name(), "password");
        assert_eq!(CredentialType::Pin.name(), "pin");
        assert_eq!(CredentialType::SecurityAnswer.name(), "security_answer");
    }

    #[test]
    fn test_is_security_answers_present() {
        assert!(is_security_answers_present("security_answer=fluffy"));
        assert!(is_security_answers_present("secret_answer: mydog"));
        assert!(is_security_answers_present(r#""security_answer": "blue""#));
        assert!(!is_security_answers_present("no security answers here"));
    }

    #[test]
    fn test_is_passphrases_present() {
        assert!(is_passphrases_present(
            "passphrase=correct horse battery staple"
        ));
        assert!(is_passphrases_present("pass_phrase: my secret words"));
        assert!(is_passphrases_present(r#""passphrase": "words""#));
        assert!(!is_passphrases_present("no passphrases here"));
    }

    #[test]
    fn test_detect_security_answers() {
        let matches = detect_security_answers("security_answer=fluffy");
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("should have one match");
        assert_eq!(first.value, "fluffy");
        assert_eq!(first.credential_type, CredentialType::SecurityAnswer);
    }

    #[test]
    fn test_detect_passphrases() {
        let matches = detect_passphrases(r#"{"passphrase": "correct horse battery staple"}"#);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("should have one match");
        assert_eq!(first.value, "correct horse battery staple");
        assert_eq!(first.credential_type, CredentialType::Passphrase);
    }

    #[test]
    fn test_detect_credentials_all_types() {
        let text = r#"{"password": "secret", "pin": "1234", "security_answer": "fluffy", "passphrase": "words"}"#;
        let matches = detect_credentials(text);

        let by_type = |t: CredentialType| matches.iter().filter(|m| m.credential_type == t).count();

        assert_eq!(by_type(CredentialType::Password), 1);
        assert_eq!(by_type(CredentialType::Pin), 1);
        assert_eq!(by_type(CredentialType::SecurityAnswer), 1);
        assert_eq!(by_type(CredentialType::Passphrase), 1);
    }

    // =========================================================================
    // Weak Pattern Detection Tests
    // =========================================================================

    #[test]
    fn test_is_weak_password() {
        // Common weak passwords
        assert!(is_weak_password("password"));
        assert!(is_weak_password("Password"));
        assert!(is_weak_password("PASSWORD"));
        assert!(is_weak_password("password123"));
        assert!(is_weak_password("test"));
        assert!(is_weak_password("admin"));
        assert!(is_weak_password("secret"));
        assert!(is_weak_password("hunter2"));
        assert!(is_weak_password("letmein"));
        assert!(is_weak_password("changeme"));
        assert!(is_weak_password("qwerty"));
        assert!(is_weak_password("123456"));
        assert!(is_weak_password("p@ssword"));
        assert!(is_weak_password("p@ssw0rd"));

        // Real passwords should not match
        assert!(!is_weak_password("x7$kL9mN@pQ2"));
        assert!(!is_weak_password("MyR3alP@ssw0rd!"));
        assert!(!is_weak_password("correct-horse-battery-staple"));
    }

    #[test]
    fn test_is_weak_pin() {
        // Common weak PINs
        assert!(is_weak_pin("0000"));
        assert!(is_weak_pin("1111"));
        assert!(is_weak_pin("1234"));
        assert!(is_weak_pin("4321"));
        assert!(is_weak_pin("9999"));
        assert!(is_weak_pin("1212"));
        assert!(is_weak_pin("123456"));

        // Random PINs should not match
        assert!(!is_weak_pin("7392"));
        assert!(!is_weak_pin("5847"));
        assert!(!is_weak_pin("962831"));
    }

    #[test]
    fn test_is_weak_security_answer() {
        // Common weak answers
        assert!(is_weak_security_answer("test"));
        assert!(is_weak_security_answer("TEST"));
        assert!(is_weak_security_answer("n/a"));
        assert!(is_weak_security_answer("N/A"));
        assert!(is_weak_security_answer("none"));
        assert!(is_weak_security_answer("null"));
        assert!(is_weak_security_answer("asdf"));
        assert!(is_weak_security_answer("placeholder"));
        assert!(is_weak_security_answer("  demo  ")); // Trimmed

        // Real answers should not match
        assert!(!is_weak_security_answer("fluffy"));
        assert!(!is_weak_security_answer(
            "my first pet was a golden retriever"
        ));
        assert!(!is_weak_security_answer("Springfield Elementary"));
    }

    #[test]
    fn test_is_weak_passphrase() {
        // Famous weak passphrases
        assert!(is_weak_passphrase("correct horse battery staple"));
        assert!(is_weak_passphrase("CORRECT HORSE BATTERY STAPLE"));
        assert!(is_weak_passphrase("test passphrase"));
        assert!(is_weak_passphrase("lorem ipsum dolor sit amet"));
        assert!(is_weak_passphrase(
            "the quick brown fox jumps over the lazy dog"
        ));

        // Real passphrases should not match
        assert!(!is_weak_passphrase("purple elephant dancing gracefully"));
        assert!(!is_weak_passphrase("my favorite coffee shop downtown"));
    }
}
