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
use super::super::common::patterns::network;

// Re-export types from shared types module
pub use super::super::types::{CredentialMatch, CredentialType};

// ============================================================================
// Quick-Check Keyword Tables
// ============================================================================
//
// These tables are scanned by `is_*_present` before invoking the more expensive
// regex matchers. Every entry must be lowercase — the input is lowercased via
// `to_lowercase()` before lookup. CJK, Arabic, and Hindi scripts have no notion
// of case, so `to_lowercase()` is identity for them and the entries below are
// in their natural form.
//
// Limitation: matching is byte-level `str::contains` and does NOT apply Unicode
// NFC/NFD normalization. Inputs that paste decomposed forms (e.g. Korean
// jamo decomposed as ㅂ+ㅣ instead of 비) will not match, the same way
// European keywords with combining diacritics would not. If a future
// regression demands NFC normalization, apply it consistently to both the
// input and these tables.

/// Keywords triggering the credential pre-filter (passwords, secrets, PINs,
/// passphrases, credentials, tokens, keys, authentication labels).
const CREDENTIAL_KEYWORDS: &[&str] = &[
    // English
    "password",
    "passwd",
    "pwd",
    "secret",
    "pin",
    "passphrase",
    "credential",
    // European: Spanish, French, German, Portuguese, Italian, Dutch
    "contrasena",
    "clave",
    "mot_de_passe",
    "passwort",
    "kennwort",
    "senha",
    "wachtwoord",
    "geheimnis",
    "segredo",
    "segreto",
    "geheim",
    // Japanese
    "パスワード",
    "秘密鍵",
    "認証",
    "暗号",
    "トークン",
    "鍵",
    "合言葉",
    // Chinese (Simplified)
    "密码",
    "密钥",
    "令牌",
    "口令",
    "凭证",
    "认证",
    // Chinese (Traditional)
    "密碼",
    "密鑰",
    "憑證",
    "認證",
    // Korean
    "비밀번호",
    "암호",
    "토큰",
    "인증",
    "비밀키",
    "암호문",
    // Arabic (space form for label text, underscore form for variable names)
    "كلمة المرور",
    "كلمة_المرور",
    "مفتاح",
    "سر",
    "رمز",
    // Hindi
    "पासवर्ड",
    "कुंजी",
    "गुप्त",
    "गुप्तकूट",
];

/// Keywords triggering the password pre-filter (password/pwd/secret family).
const PASSWORD_KEYWORDS: &[&str] = &[
    // English
    "password",
    "passwd",
    "pwd",
    "pass",
    "secret",
    "credential",
    // European
    "contrasena",
    "clave",
    "mot_de_passe",
    "passwort",
    "kennwort",
    "senha",
    "wachtwoord",
    "geheimnis",
    "segredo",
    "segreto",
    "geheim",
    // Japanese
    "パスワード",
    "秘密鍵",
    "暗号",
    "鍵",
    // Chinese (Simplified)
    "密码",
    "密钥",
    "口令",
    "凭证",
    // Chinese (Traditional)
    "密碼",
    "密鑰",
    "憑證",
    // Korean
    "비밀번호",
    "암호",
    "비밀키",
    // Arabic
    "كلمة المرور",
    "كلمة_المرور",
    "مفتاح",
    "سر",
    // Hindi
    "पासवर्ड",
    "कुंजी",
    "गुप्त",
];

/// Keywords triggering the passphrase pre-filter.
const PASSPHRASE_KEYWORDS: &[&str] = &[
    // English
    "passphrase",
    "pass_phrase",
    // European
    "frase_de_paso",
    "phrase_de_passe",
    "kennphrase",
    "frase_secreta",
    "wachtwoordzin",
    // Japanese
    "合言葉",
    // Chinese (Simplified)
    "口令",
    // Korean
    "암호문",
    // Hindi
    "गुप्तकूट",
];

// Detection functions

/// Check if text contains any credential patterns
///
/// Quick check without extracting matches.
#[must_use]
pub fn is_credentials_present(text: &str) -> bool {
    let lower = text.to_lowercase();

    // Quick keyword check first (English + international translations)
    if !CREDENTIAL_KEYWORDS.iter().any(|k| lower.contains(k)) {
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
    if !PASSWORD_KEYWORDS.iter().any(|k| lower.contains(k)) {
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
    if !PASSPHRASE_KEYWORDS.iter().any(|k| lower.contains(k)) {
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
// Connection String Detection
// ============================================================================

/// Known database URL schemes
const DB_SCHEMES: &[&str] = &[
    "postgres://",
    "postgresql://",
    "mysql://",
    "mongodb://",
    "mongodb+srv://",
    "redis://",
    "rediss://",
    "amqp://",
    "amqps://",
    "mqtt://",
    "mqtts://",
];

/// Check if value is a connection string with embedded credentials
///
/// Detects URL-based connection strings (postgres://, mysql://, etc.),
/// MSSQL key-value format (Server=...;Password=...), and JDBC with
/// password parameters.
#[must_use]
pub fn is_connection_string_with_credentials(value: &str) -> bool {
    let trimmed = value.trim();
    network::CONNECTION_STRING_DB_URL.is_match(trimmed)
        || network::CONNECTION_STRING_MSSQL.is_match(trimmed)
        || network::CONNECTION_STRING_JDBC.is_match(trimmed)
}

/// Check if value is a database connection string (URL-based)
///
/// Returns true if the value uses a known database URL scheme
/// (postgres://, mysql://, mongodb://, redis://, amqp://, mqtt://).
/// Does NOT require credentials to be present.
#[must_use]
pub fn is_database_connection_string(value: &str) -> bool {
    let lower = value.trim().to_lowercase();
    DB_SCHEMES.iter().any(|scheme| lower.starts_with(scheme))
}

/// Find all connection strings with credentials in text
#[must_use]
pub fn find_connection_strings_in_text(text: &str) -> Vec<CredentialMatch> {
    let mut matches = Vec::new();

    // URL-based database connection strings
    for m in network::CONNECTION_STRING_DB_URL.find_iter(text) {
        matches.push(CredentialMatch {
            start: m.start(),
            end: m.end(),
            value: m.as_str().to_string(),
            credential_type: CredentialType::Generic,
            label: "connection_string".to_string(),
        });
    }

    // MSSQL key-value connection strings
    for m in network::CONNECTION_STRING_MSSQL.find_iter(text) {
        let start = m.start();
        if !matches.iter().any(|existing| existing.start == start) {
            matches.push(CredentialMatch {
                start,
                end: m.end(),
                value: m.as_str().to_string(),
                credential_type: CredentialType::Generic,
                label: "connection_string".to_string(),
            });
        }
    }

    // JDBC connection strings
    for m in network::CONNECTION_STRING_JDBC.find_iter(text) {
        let start = m.start();
        if !matches.iter().any(|existing| existing.start == start) {
            matches.push(CredentialMatch {
                start,
                end: m.end(),
                value: m.as_str().to_string(),
                credential_type: CredentialType::Generic,
                label: "connection_string".to_string(),
            });
        }
    }

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
    fn test_is_passwords_present_international() {
        // Spanish
        assert!(is_passwords_present("contrasena=secreto123"));
        assert!(is_passwords_present("clave=valor"));
        // French
        assert!(is_passwords_present("mot_de_passe=secret123"));
        // German
        assert!(is_passwords_present("passwort=geheim123"));
        assert!(is_passwords_present("kennwort=test123"));
        // Portuguese
        assert!(is_passwords_present("senha=segredo123"));
        // Dutch
        assert!(is_passwords_present("wachtwoord=geheim123"));
        // Italian
        assert!(is_passwords_present("segreto=valore123"));
    }

    #[test]
    fn test_is_credentials_present_international() {
        assert!(is_credentials_present("contrasena=secreto"));
        assert!(is_credentials_present("passwort=geheim"));
        assert!(is_credentials_present("senha=segredo"));
        assert!(is_credentials_present("wachtwoord=geheim"));
        assert!(is_credentials_present("frase_de_paso=palabras secretas"));
        assert!(!is_credentials_present("just some german text"));
    }

    #[test]
    fn test_detect_passwords_international() {
        let matches = detect_passwords("passwort=geheim123");
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("should detect German password");
        assert_eq!(first.value, "geheim123");

        let matches = detect_passwords("contrasena=secreto123");
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("should detect Spanish password");
        assert_eq!(first.value, "secreto123");

        let matches = detect_passwords("senha=segredo123");
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("should detect Portuguese password");
        assert_eq!(first.value, "segredo123");
    }

    // ------------------------------------------------------------------------
    // CJK / Arabic / Hindi keyword tests (Issue #35)
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_passwords_present_cjk() {
        // Japanese
        assert!(is_passwords_present("パスワード=secret123"));
        // Chinese Simplified
        assert!(is_passwords_present("密码=secret123"));
        // Chinese Traditional
        assert!(is_passwords_present("密碼=secret123"));
        // Korean
        assert!(is_passwords_present("비밀번호=secret123"));
    }

    #[test]
    fn test_is_passwords_present_arabic_hindi() {
        // Arabic: both space and underscore variants
        assert!(is_passwords_present("كلمة المرور: secret123"));
        assert!(is_passwords_present("كلمة_المرور=secret123"));
        // Hindi
        assert!(is_passwords_present("पासवर्ड=secret123"));
    }

    #[test]
    fn test_is_credentials_present_cjk_arabic_hindi() {
        assert!(is_credentials_present("パスワード=secret"));
        assert!(is_credentials_present("密码=secret"));
        assert!(is_credentials_present("비밀번호=secret"));
        assert!(is_credentials_present("كلمة المرور: secret"));
        assert!(is_credentials_present("पासवर्ड=secret"));

        // Plain non-Latin text without a credential keyword must not trip the filter.
        assert!(!is_credentials_present("日本語のテキスト"));
        assert!(!is_credentials_present("中文文本"));
        assert!(!is_credentials_present("نص عربي عام"));
        assert!(!is_credentials_present("सामान्य हिंदी पाठ"));
    }

    #[test]
    fn test_is_passphrases_present_cjk_hindi() {
        // Japanese passphrase
        assert!(is_passphrases_present(
            "合言葉=correct horse battery staple"
        ));
        // Korean passphrase
        assert!(is_passphrases_present("암호문: my secret words"));
        // Hindi passphrase
        assert!(is_passphrases_present("गुप्तकूट=correct horse battery staple"));
    }

    #[test]
    fn test_detect_passwords_cjk() {
        let matches = detect_passwords("パスワード=hunter2");
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("should detect Japanese password");
        assert_eq!(first.value, "hunter2");
        assert_eq!(first.label, "パスワード");
        assert_eq!(first.credential_type, CredentialType::Password);
    }

    #[test]
    fn test_detect_passwords_mixed_scripts_json() {
        // Real-world style multilingual config — one document with several
        // languages of password labels. Each should be detected and captured.
        let text = r#"{"パスワード": "ja_secret", "密码": "zh_secret", "비밀번호": "ko_secret"}"#;
        let matches = detect_passwords(text);
        assert_eq!(matches.len(), 3);

        let values: Vec<&str> = matches.iter().map(|m| m.value.as_str()).collect();
        assert!(values.contains(&"ja_secret"));
        assert!(values.contains(&"zh_secret"));
        assert!(values.contains(&"ko_secret"));
    }

    #[test]
    fn test_english_european_still_works_after_refactor() {
        // Smoke regression for the .contains() → const slice refactor.
        // Each branch of the old chain is exercised here.
        assert!(is_passwords_present("password=secret"));
        assert!(is_passwords_present("passwd=secret"));
        assert!(is_passwords_present("pwd=secret"));
        assert!(is_passwords_present("contrasena=secreto"));
        assert!(is_passwords_present("passwort=geheim"));
        assert!(is_passwords_present("senha=segredo"));
        assert!(is_passwords_present("wachtwoord=geheim"));
        assert!(is_passwords_present("segreto=valore"));
        assert!(!is_passwords_present("no credentials here"));

        assert!(is_passphrases_present(
            "passphrase=correct horse battery staple"
        ));
        assert!(is_passphrases_present(
            "frase_de_paso=palabras secretas aqui"
        ));
        assert!(!is_passphrases_present(
            "just regular text without keywords"
        ));
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
    // Connection String Detection Tests
    // =========================================================================

    #[test]
    fn test_is_connection_string_with_credentials_postgres() {
        assert!(is_connection_string_with_credentials(
            "postgres://admin:secret@db.example.com/mydb"
        ));
        assert!(is_connection_string_with_credentials(
            "postgresql://user:p@ss@localhost:5432/test"
        ));
    }

    #[test]
    fn test_is_connection_string_with_credentials_mysql() {
        assert!(is_connection_string_with_credentials(
            "mysql://root:password123@db.example.com:3306/app"
        ));
    }

    #[test]
    fn test_is_connection_string_with_credentials_mongodb() {
        assert!(is_connection_string_with_credentials(
            "mongodb://admin:secret@mongo.example.com:27017/mydb"
        ));
        assert!(is_connection_string_with_credentials(
            "mongodb+srv://user:pass@cluster0.example.net/test"
        ));
    }

    #[test]
    fn test_is_connection_string_with_credentials_redis() {
        assert!(is_connection_string_with_credentials(
            "redis://default:password@redis.example.com:6379"
        ));
    }

    #[test]
    fn test_is_connection_string_with_credentials_mssql() {
        assert!(is_connection_string_with_credentials(
            "Server=db.example.com;Database=mydb;Password=secret123"
        ));
        assert!(is_connection_string_with_credentials(
            "Data Source=myserver;Pwd=hunter2"
        ));
    }

    #[test]
    fn test_is_connection_string_with_credentials_jdbc() {
        assert!(is_connection_string_with_credentials(
            "jdbc:postgresql://host/db?password=secret"
        ));
    }

    #[test]
    fn test_is_connection_string_without_credentials() {
        // URL without credentials
        assert!(!is_connection_string_with_credentials(
            "https://example.com"
        ));
        // Database URL without password
        assert!(!is_connection_string_with_credentials(
            "postgres://db.example.com/mydb"
        ));
        // Plain text
        assert!(!is_connection_string_with_credentials("just plain text"));
    }

    #[test]
    fn test_is_database_connection_string() {
        assert!(is_database_connection_string(
            "postgres://admin:secret@host/db"
        ));
        assert!(is_database_connection_string(
            "mysql://root:pw@host:3306/app"
        ));
        assert!(is_database_connection_string("mongodb://user:pass@host/db"));
        assert!(is_database_connection_string("redis://default:pw@host"));
        assert!(is_database_connection_string("amqp://guest:guest@host"));

        assert!(!is_database_connection_string("https://example.com"));
        assert!(!is_database_connection_string("ftp://files.example.com"));
    }

    #[test]
    fn test_find_connection_strings_in_text() {
        let text = "Connect to postgres://admin:secret@db.example.com/mydb for the database";
        let matches = find_connection_strings_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("expected at least one match");
        assert!(first.value.contains("postgres://"));
    }

    #[test]
    fn test_find_connection_strings_special_chars() {
        let text = "postgres://user:p%40ss%3Aw0rd!@host/db";
        let matches = find_connection_strings_in_text(text);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_find_connection_strings_multiple() {
        let text = "DB1: postgres://u:p@host1/db1 and DB2: mysql://u:p@host2/db2";
        let matches = find_connection_strings_in_text(text);
        assert_eq!(matches.len(), 2);
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
