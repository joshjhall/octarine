//! Shared regex patterns for credential detection in text
//!
//! This module provides reusable regex patterns for scanning text documents
//! to find credential values (passwords, PINs, security answers, passphrases).
//!
//! # Key Difference from Other Patterns
//!
//! Unlike SSN or email patterns that match a specific format, credential patterns
//! are **context-based**: they detect labels/keys and capture the following value.
//!
//! # Pattern Categories
//!
//! - **Password**: password=, passwd:, pwd=, secret=, credential=
//! - **PIN**: pin=, pin_code=, security_code=
//! - **Security Answer**: security_answer=, secret_answer=
//! - **Passphrase**: passphrase=, pass_phrase=
//!
//! # Design Principles
//!
//! - **Context-based**: Match label + value, not value format
//! - **Format-aware**: Support key=value, key: value, JSON, YAML
//! - **Conservative**: Prefer false negatives over false positives

// SAFETY: All regex patterns in this module are hardcoded and verified at compile time.
// Regex::new() only fails on invalid syntax, which would be caught during development/testing.
// Using expect() here is safe because these patterns are static and never change at runtime.
#![allow(clippy::expect_used)]

use once_cell::sync::Lazy;
use regex::Regex;

/// Password field patterns
pub mod password {
    use super::*;

    /// Password field pattern (key=value or key: value format)
    /// Captures: (label) (value)
    /// Example: "password=secret123" → ("password=", "secret123")
    /// Example: "passwort=geheim123" → ("passwort=", "geheim123")
    ///
    /// Supports English + Spanish, French, German, Portuguese, Italian, Dutch translations.
    pub static FIELD: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?i)\b(password|passwd|pwd|pass|secret|credential|contrasena|contrasenya|clave|mot_de_passe|motdepasse|passwort|kennwort|senha|wachtwoord|secreto|geheimnis|segredo|segreto|geheim)\s*[:=]\s*['"]?([^\s'"}\]]+)['"]?"#,
        )
        .expect("BUG: Invalid password field regex")
    });

    /// JSON password pattern ("password": "value")
    /// Captures: (key) (value)
    /// Example: {"password": "hunter2"} → ("password", "hunter2")
    ///
    /// Supports English + Spanish, French, German, Portuguese, Italian, Dutch translations.
    pub static JSON: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"["'](password|passwd|pwd|pass|secret|credential|contrasena|contrasenya|clave|mot_de_passe|motdepasse|passwort|kennwort|senha|wachtwoord|secreto|geheimnis|segredo|segreto|geheim)["']\s*:\s*["']([^"']+)["']"#)
            .expect("BUG: Invalid JSON password regex")
    });

    /// Returns all password patterns in priority order
    pub fn all() -> Vec<&'static Regex> {
        vec![&*JSON, &*FIELD]
    }
}

/// PIN field patterns
pub mod pin {
    use super::*;

    /// PIN field pattern (key=value or key: value format)
    /// Captures: (label) (value)
    /// Example: "pin=1234" → ("pin=", "1234")
    /// Note: Uses word boundary \b to ensure exact digit count (4-8)
    pub static FIELD: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\b(pin|pin_code|pincode|security_code)\s*[:=]\s*['"]?(\d{4,8})\b['"]?"#)
            .expect("BUG: Invalid PIN field regex")
    });

    /// JSON PIN pattern ("pin": "1234" or "pin": 1234)
    /// Captures: (key) (value)
    pub static JSON: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"["'](pin|pin_code|pincode|security_code)["']\s*:\s*["']?(\d{4,8})\b["']?"#)
            .expect("BUG: Invalid JSON PIN regex")
    });

    /// Returns all PIN patterns in priority order
    pub fn all() -> Vec<&'static Regex> {
        vec![&*JSON, &*FIELD]
    }
}

/// Security question/answer patterns
pub mod security_answer {
    use super::*;

    /// Security answer field pattern
    /// Captures: (label) (value)
    pub static FIELD: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?i)\b(security_answer|secret_answer|answer|security_question_answer)\s*[:=]\s*['"]?([^\s'"}\]]+)['"]?"#,
        )
        .expect("BUG: Invalid security answer field regex")
    });

    /// JSON security answer pattern
    pub static JSON: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"["'](security_answer|secret_answer|security_question_answer)["']\s*:\s*["']([^"']+)["']"#,
        )
        .expect("BUG: Invalid JSON security answer regex")
    });

    /// Returns all security answer patterns in priority order
    pub fn all() -> Vec<&'static Regex> {
        vec![&*JSON, &*FIELD]
    }
}

/// Passphrase field patterns
pub mod passphrase {
    use super::*;

    /// Passphrase field pattern
    /// Captures: (label) (value)
    /// Note: Passphrases can contain spaces, so we capture until end of line or closing bracket/quote
    ///
    /// Supports English + Spanish, French, German, Portuguese, Dutch translations.
    pub static FIELD: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?i)\b(passphrase|pass_phrase|frase_de_paso|phrase_de_passe|kennphrase|frase_secreta|wachtwoordzin)\s*[:=]\s*['"]?([^'"}\]]+?)['"]?(?:\s|$|[}\]])"#,
        )
        .expect("BUG: Invalid passphrase field regex")
    });

    /// JSON passphrase pattern
    ///
    /// Supports English + Spanish, French, German, Portuguese, Dutch translations.
    pub static JSON: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"["'](passphrase|pass_phrase|frase_de_paso|phrase_de_passe|kennphrase|frase_secreta|wachtwoordzin)["']\s*:\s*["']([^"']+)["']"#)
            .expect("BUG: Invalid JSON passphrase regex")
    });

    /// Returns all passphrase patterns in priority order
    pub fn all() -> Vec<&'static Regex> {
        vec![&*JSON, &*FIELD]
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ==================== PASSWORD TESTS ====================

    #[test]
    fn test_password_field_equals() {
        assert!(password::FIELD.is_match("password=secret123"));
        assert!(password::FIELD.is_match("PASSWORD=Secret"));
        assert!(password::FIELD.is_match("passwd=hunter2"));
        assert!(password::FIELD.is_match("pwd=test"));
        assert!(password::FIELD.is_match("secret=myvalue"));
        assert!(password::FIELD.is_match("credential=abc123"));
    }

    #[test]
    fn test_password_field_colon() {
        assert!(password::FIELD.is_match("password: secret123"));
        assert!(password::FIELD.is_match("password:secret123"));
        assert!(password::FIELD.is_match("PASSWORD : Secret"));
    }

    #[test]
    fn test_password_field_quoted() {
        assert!(password::FIELD.is_match("password='secret123'"));
        assert!(password::FIELD.is_match("password=\"secret123\""));
    }

    #[test]
    fn test_password_json() {
        assert!(password::JSON.is_match(r#""password": "hunter2""#));
        assert!(password::JSON.is_match(r#"'password': 'hunter2'"#));
        assert!(password::JSON.is_match(r#""pwd": "test""#));
        assert!(password::JSON.is_match(r#""secret": "value""#));
    }

    #[test]
    fn test_password_captures() {
        let caps = password::FIELD
            .captures("password=secret123")
            .expect("should match");
        assert_eq!(caps.get(1).expect("group 1").as_str(), "password");
        assert_eq!(caps.get(2).expect("group 2").as_str(), "secret123");
    }

    // ==================== PIN TESTS ====================

    #[test]
    fn test_pin_field() {
        assert!(pin::FIELD.is_match("pin=1234"));
        assert!(pin::FIELD.is_match("PIN: 5678"));
        assert!(pin::FIELD.is_match("pin_code=123456"));
        assert!(pin::FIELD.is_match("security_code=1234"));
    }

    #[test]
    fn test_pin_json() {
        assert!(pin::JSON.is_match(r#""pin": "1234""#));
        assert!(pin::JSON.is_match(r#""pin": 5678"#));
        assert!(pin::JSON.is_match(r#""pin_code": "123456""#));
    }

    #[test]
    fn test_pin_length_limits() {
        // Should match 4-8 digits
        assert!(pin::FIELD.is_match("pin=1234")); // 4 digits
        assert!(pin::FIELD.is_match("pin=12345678")); // 8 digits

        // Should NOT match <4 or >8 digits
        assert!(!pin::FIELD.is_match("pin=123")); // 3 digits
        assert!(!pin::FIELD.is_match("pin=123456789")); // 9 digits
    }

    // ==================== SECURITY ANSWER TESTS ====================

    #[test]
    fn test_security_answer_field() {
        assert!(security_answer::FIELD.is_match("security_answer=fluffy"));
        assert!(security_answer::FIELD.is_match("secret_answer=mydog"));
        assert!(security_answer::FIELD.is_match("answer=blue"));
    }

    #[test]
    fn test_security_answer_json() {
        assert!(security_answer::JSON.is_match(r#""security_answer": "fluffy""#));
        assert!(security_answer::JSON.is_match(r#""secret_answer": "mydog""#));
    }

    // ==================== PASSPHRASE TESTS ====================

    #[test]
    fn test_passphrase_field() {
        assert!(passphrase::FIELD.is_match("passphrase=correct horse battery staple"));
        assert!(passphrase::FIELD.is_match("pass_phrase: my secret words"));
    }

    #[test]
    fn test_passphrase_json() {
        assert!(passphrase::JSON.is_match(r#""passphrase": "correct horse battery staple""#));
    }

    // ==================== INTERNATIONAL KEYWORD TESTS ====================

    #[test]
    fn test_password_field_spanish() {
        assert!(password::FIELD.is_match("contrasena=secreto123"));
        assert!(password::FIELD.is_match("contrasenya=valor"));
        assert!(password::FIELD.is_match("clave=mipassword"));
        assert!(password::FIELD.is_match("secreto=valor123"));
    }

    #[test]
    fn test_password_field_french() {
        assert!(password::FIELD.is_match("mot_de_passe=secret123"));
        assert!(password::FIELD.is_match("motdepasse=valeur"));
    }

    #[test]
    fn test_password_field_german() {
        assert!(password::FIELD.is_match("passwort=geheim123"));
        assert!(password::FIELD.is_match("kennwort=test123"));
        assert!(password::FIELD.is_match("geheimnis=wert"));
        assert!(password::FIELD.is_match("geheim=wert123"));
    }

    #[test]
    fn test_password_field_portuguese() {
        assert!(password::FIELD.is_match("senha=segredo123"));
        assert!(password::FIELD.is_match("segredo=valor"));
    }

    #[test]
    fn test_password_field_italian() {
        assert!(password::FIELD.is_match("segreto=valore123"));
    }

    #[test]
    fn test_password_field_dutch() {
        assert!(password::FIELD.is_match("wachtwoord=geheim123"));
    }

    #[test]
    fn test_password_json_international() {
        assert!(password::JSON.is_match(r#""contrasena": "secreto123""#));
        assert!(password::JSON.is_match(r#""passwort": "geheim123""#));
        assert!(password::JSON.is_match(r#""senha": "segredo123""#));
        assert!(password::JSON.is_match(r#""wachtwoord": "geheim123""#));
        assert!(password::JSON.is_match(r#""mot_de_passe": "secret123""#));
        assert!(password::JSON.is_match(r#""clave": "valor123""#));
    }

    #[test]
    fn test_passphrase_field_international() {
        assert!(passphrase::FIELD.is_match("frase_de_paso=palabras secretas aqui"));
        assert!(passphrase::FIELD.is_match("phrase_de_passe: mes mots secrets"));
        assert!(passphrase::FIELD.is_match("kennphrase=meine geheimen worte"));
        assert!(passphrase::FIELD.is_match("frase_secreta=minhas palavras"));
        assert!(passphrase::FIELD.is_match("wachtwoordzin=mijn geheime woorden"));
    }

    #[test]
    fn test_passphrase_json_international() {
        assert!(passphrase::JSON.is_match(r#""frase_de_paso": "palabras secretas""#));
        assert!(passphrase::JSON.is_match(r#""kennphrase": "geheime worte""#));
    }

    // ==================== FALSE POSITIVE TESTS ====================

    #[test]
    fn test_password_false_positives() {
        // Should NOT match without assignment
        assert!(!password::FIELD.is_match("password"));
        assert!(!password::FIELD.is_match("the password is"));

        // Should NOT match in other contexts
        assert!(!password::FIELD.is_match("forgot_password_link"));
    }

    #[test]
    fn test_pin_false_positives() {
        // Should NOT match non-numeric
        assert!(!pin::FIELD.is_match("pin=abcd"));

        // Should NOT match without proper label
        assert!(!pin::FIELD.is_match("1234"));
    }
}
