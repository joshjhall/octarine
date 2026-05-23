// Static regex patterns are compile-time-known-valid; expect is intentional.
#![allow(clippy::expect_used)]
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

use once_cell::sync::Lazy;
use regex::Regex;

use crate::primitives::data::tokens::RedactionTokenCore;

use super::super::common::patterns::network;
use super::detection::{self, CredentialMatch, CredentialType};
use super::framework;
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

// Connection string redaction

/// Regex for password portion of a URL-based connection string
static URL_PASSWORD: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(://[^:@\s]+:)([^@\s]+)(@)").expect("BUG: Invalid regex pattern"));

/// Regex for password in MSSQL key-value connection string
static MSSQL_PASSWORD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)((?:Password|Pwd)=)([^;\s]+)").expect("BUG: Invalid regex pattern")
});

/// Regex for password in JDBC query parameter
static JDBC_PASSWORD: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(password=)([^\s&;]+)").expect("BUG: Invalid regex pattern"));

/// Regex for password in JDBC Oracle thin connection string
/// Captures: (1) prefix up to `/`, (2) password, (3) `@host`
static ORACLE_THIN_PASSWORD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(jdbc:oracle:[a-z]+:[^/\s:@]+/)([^@\s]+)(@)")
        .expect("BUG: Invalid regex pattern")
});

/// Redact credentials in a connection string while preserving host/database
///
/// - URL format: `postgres://admin:****@db.example.com/mydb`
/// - MSSQL: `Server=db.example.com;Password=****;Database=mydb`
/// - JDBC: `jdbc:postgresql://host/db?password=****`
/// - JDBC SQL Server: `jdbc:sqlserver://host;user=sa;password=****`
/// - JDBC Oracle thin: `jdbc:oracle:thin:scott/****@host:1521:orcl`
#[must_use]
pub fn redact_connection_string(value: &str) -> String {
    let mut result = value.to_string();

    // URL-based: replace user:PASSWORD@host with user:****@host
    if URL_PASSWORD.is_match(&result) {
        result = URL_PASSWORD
            .replace_all(&result, "${1}****${3}")
            .to_string();
    }

    // JDBC Oracle thin: replace user/PASSWORD@host with user/****@host
    if ORACLE_THIN_PASSWORD.is_match(&result) {
        result = ORACLE_THIN_PASSWORD
            .replace_all(&result, "${1}****${3}")
            .to_string();
    }

    // MSSQL key-value: replace Password=VALUE with Password=****
    if MSSQL_PASSWORD.is_match(&result) {
        result = MSSQL_PASSWORD.replace_all(&result, "${1}****").to_string();
    }

    // JDBC query param: replace password=VALUE with password=****
    if JDBC_PASSWORD.is_match(&result) {
        result = JDBC_PASSWORD.replace_all(&result, "${1}****").to_string();
    }

    result
}

/// Redact all connection strings in text while preserving host/database info
#[must_use]
pub fn redact_connection_strings_in_text(text: &str) -> Cow<'_, str> {
    let matches = detection::find_connection_strings_in_text(text);
    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();

    // Replace from end to start to preserve positions
    for m in matches.iter().rev() {
        let redacted = redact_connection_string(&m.value);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

// Framework credential redaction

/// Redact the value of a framework credential match while preserving the key
///
/// Recognizes the same shapes as `is_framework_credential_present`:
/// - Django: `'PASSWORD': 'secret'` -> `'PASSWORD': '****'`
/// - Rails YAML: `password: secret` -> `password: ****`
/// - .env: `DB_PASSWORD=secret` -> `DB_PASSWORD=****`
/// - Docker Compose: `MYSQL_ROOT_PASSWORD: secret` -> `MYSQL_ROOT_PASSWORD: ****`
///
/// If `value` does not match any framework pattern, it is returned unchanged.
#[must_use]
pub fn redact_framework_credential(value: &str) -> String {
    let mut result = value.to_string();

    // Django: replace 'PASSWORD': 'V' with 'PASSWORD': '****' (same for double quotes)
    if network::FRAMEWORK_DJANGO_PASSWORD.is_match(&result) {
        result = redact_framework_django(&result);
    }

    // Rails YAML: replace `password: V` with `password: ****` (preserve indent and `#`)
    if network::FRAMEWORK_RAILS_YAML_PASSWORD.is_match(&result) {
        result = redact_framework_rails_yaml(&result);
    }

    // .env: replace `KEY=V` with `KEY=****`
    if network::FRAMEWORK_ENV_DB_PASSWORD.is_match(&result) {
        result = redact_framework_env(&result);
    }

    // Docker Compose: replace `KEY=V` or `KEY: V` with same separator + `****`
    if network::FRAMEWORK_DOCKER_COMPOSE_PASSWORD.is_match(&result) {
        result = redact_framework_docker_compose(&result);
    }

    result
}

/// Redact all framework-style credentials in text
#[must_use]
pub fn redact_framework_credentials_in_text(text: &str) -> Cow<'_, str> {
    let matches = framework::find_framework_credentials_in_text(text);
    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();

    // Replace from end to start to preserve positions. Each match covers the
    // full key=value (or key: value) span — pass that whole slice to
    // `redact_framework_credential` so its regexes can locate the value.
    for m in matches.iter().rev() {
        if let Some(full_match) = text.get(m.start..m.end) {
            let redacted = redact_framework_credential(full_match);
            result.replace_range(m.start..m.end, &redacted);
        }
    }

    Cow::Owned(result)
}

fn redact_framework_django(value: &str) -> String {
    // Two alternations: '…'…'…' and "…"…"…". Replace the inner value.
    let single = Lazy::new(|| {
        Regex::new(r"('PASSWORD'\s*:\s*')([^']+)(')").expect("BUG: Invalid regex pattern")
    });
    let double = Lazy::new(|| {
        Regex::new(r#"("PASSWORD"\s*:\s*")([^"]+)(")"#).expect("BUG: Invalid regex pattern")
    });
    let mut result = single.replace_all(value, "${1}****${3}").to_string();
    result = double.replace_all(&result, "${1}****${3}").to_string();
    result
}

fn redact_framework_rails_yaml(value: &str) -> String {
    // Capture the prefix (indent + optional `#` + key + `:` + whitespace) and replace the value.
    static RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?im)(^[ \t]*#?[ \t]*password[ \t]*:[ \t]+)(\S+)")
            .expect("BUG: Invalid regex pattern")
    });
    RE.replace_all(value, "${1}****").to_string()
}

fn redact_framework_env(value: &str) -> String {
    static RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?m)(^[ \t]*#?[ \t]*(?:DB_PASSWORD|DATABASE_PASSWORD|REDIS_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|POSTGRESQL_PASSWORD|MONGO_PASSWORD)[ \t]*=[ \t]*)(\S+)",
        )
        .expect("BUG: Invalid regex pattern")
    });
    RE.replace_all(value, "${1}****").to_string()
}

fn redact_framework_docker_compose(value: &str) -> String {
    static RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?m)(^[ \t]*#?[ \t]*-?[ \t]*(?:MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|RABBITMQ_DEFAULT_PASS|REDIS_PASSWORD)[ \t]*[=:][ \t]*)(\S+)",
        )
        .expect("BUG: Invalid regex pattern")
    });
    RE.replace_all(value, "${1}****").to_string()
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

    // Connection string redaction tests

    #[test]
    fn test_redact_connection_string_url() {
        let result = redact_connection_string("postgres://admin:secret@db.example.com/mydb");
        assert_eq!(result, "postgres://admin:****@db.example.com/mydb");
        assert!(!result.contains("secret"));
    }

    #[test]
    fn test_redact_connection_string_mssql() {
        let result =
            redact_connection_string("Server=db.example.com;Password=secret123;Database=mydb");
        assert_eq!(result, "Server=db.example.com;Password=****;Database=mydb");
        assert!(!result.contains("secret123"));
    }

    #[test]
    fn test_redact_connection_string_jdbc() {
        let result = redact_connection_string("jdbc:postgresql://host/db?password=secret");
        assert_eq!(result, "jdbc:postgresql://host/db?password=****");
        assert!(!result.contains("secret"));
    }

    #[test]
    fn test_redact_connection_string_preserves_host() {
        let result = redact_connection_string("mysql://root:p@ssword@db.prod.example.com:3306/app");
        assert!(result.contains("db.prod.example.com"));
        assert!(result.contains("3306"));
        assert!(result.contains("****"));
    }

    #[test]
    fn test_redact_connection_strings_in_text_basic() {
        let text = "Connect to postgres://admin:secret@db.example.com/mydb for data";
        let result = redact_connection_strings_in_text(text);
        assert!(result.contains("****"));
        assert!(!result.contains("secret"));
        assert!(result.contains("db.example.com"));
    }

    #[test]
    fn test_redact_connection_strings_in_text_no_match() {
        let text = "just regular text";
        let result = redact_connection_strings_in_text(text);
        assert_eq!(result, text);
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

    // ========================================================================
    // JDBC variant + framework redaction (issue #30)
    // ========================================================================

    #[test]
    fn test_redact_connection_string_jdbc_oracle_thin() {
        let result = redact_connection_string("jdbc:oracle:thin:scott/tiger@dbhost:1521:orcl");
        assert!(result.contains("scott/****@"));
        assert!(!result.contains("tiger"));
        assert!(result.contains("dbhost:1521:orcl"));
    }

    #[test]
    fn test_redact_connection_string_jdbc_sqlserver() {
        let result =
            redact_connection_string("jdbc:sqlserver://server:1433;user=sa;password=secret");
        assert!(result.contains("password=****"));
        assert!(!result.contains("secret"));
        // MSSQL_PASSWORD covers password=… semicolon form too (case-insensitive).
        assert!(result.contains("user=sa"));
    }

    #[test]
    fn test_redact_framework_credential_django() {
        assert_eq!(
            redact_framework_credential("'PASSWORD': 'secret'"),
            "'PASSWORD': '****'"
        );
        assert_eq!(
            redact_framework_credential(r#""PASSWORD": "secret""#),
            r#""PASSWORD": "****""#
        );
    }

    #[test]
    fn test_redact_framework_credential_env() {
        assert_eq!(
            redact_framework_credential("DB_PASSWORD=secret123"),
            "DB_PASSWORD=****"
        );
        assert_eq!(
            redact_framework_credential("REDIS_PASSWORD=foobar"),
            "REDIS_PASSWORD=****"
        );
    }

    #[test]
    fn test_redact_framework_credential_rails_yaml() {
        assert_eq!(
            redact_framework_credential("  password: secret"),
            "  password: ****"
        );
    }

    #[test]
    fn test_redact_framework_credential_docker_compose() {
        assert_eq!(
            redact_framework_credential("  - MYSQL_ROOT_PASSWORD=secret"),
            "  - MYSQL_ROOT_PASSWORD=****"
        );
        assert_eq!(
            redact_framework_credential("MYSQL_ROOT_PASSWORD: secret"),
            "MYSQL_ROOT_PASSWORD: ****"
        );
    }

    #[test]
    fn test_redact_framework_credentials_in_text_mixed() {
        let text = "\
DATABASES = {'default': {'PASSWORD': 'pg_secret'}}
DB_PASSWORD=dotenv_secret
";
        let result = redact_framework_credentials_in_text(text);
        assert!(!result.contains("pg_secret"));
        assert!(!result.contains("dotenv_secret"));
        assert!(result.contains("****"));
        assert!(result.contains("DB_PASSWORD"));
        assert!(result.contains("PASSWORD"));
    }

    #[test]
    fn test_redact_framework_credentials_in_text_no_match() {
        let text = "APP_HOST=localhost\nAPP_PORT=3000\n";
        let result = redact_framework_credentials_in_text(text);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_framework_credential_idempotent() {
        let once = redact_framework_credential("DB_PASSWORD=secret");
        let twice = redact_framework_credential(&once);
        assert_eq!(once, twice);
    }
}
