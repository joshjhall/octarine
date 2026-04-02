//! Charset classification for entropy analysis
//!
//! Different character sets have different theoretical maximum entropy,
//! requiring different detection thresholds:
//! - Base64 max ~6.0 bits/char (threshold 4.5)
//! - Hex max ~4.0 bits/char (threshold 3.0)
//!
//! Classification enables the detection logic to apply per-charset thresholds,
//! following detect-secrets conventions for character set definitions.

// ============================================================================
// Types
// ============================================================================

/// Character set classification for entropy threshold selection
///
/// Strings are classified by their character membership to determine
/// the appropriate entropy threshold. More restrictive charsets (Hex)
/// have lower maximum entropy than broader ones (Base64).
///
/// # Classification Priority
///
/// When a string could belong to multiple charsets (e.g., `"abcdef"` is
/// valid Hex and valid Base64), the most restrictive match wins:
/// Hex → Alphanumeric → Base64 → Unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CharsetClass {
    /// Base64 charset: `A-Za-z0-9+/=-_`
    /// Includes standard Base64, URL-safe variant, and padding character.
    /// Theoretical max entropy: ~6.0 bits/char.
    Base64,

    /// Hexadecimal charset: `0-9a-fA-F`
    /// Theoretical max entropy: ~4.0 bits/char.
    Hex,

    /// Alphanumeric charset: `A-Za-z0-9` only (no special characters)
    /// Theoretical max entropy: ~5.95 bits/char.
    Alphanumeric,

    /// Mixed or unrecognized character set
    Unknown,
}

// ============================================================================
// Classification Functions
// ============================================================================

/// Classify a string's character set
///
/// Examines all characters in the string and returns the most restrictive
/// charset that contains them all.
///
/// # Priority
///
/// Hex (most restrictive) → Alphanumeric → Base64 → Unknown
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::entropy::charsets::{classify_charset, CharsetClass};
///
/// assert_eq!(classify_charset("deadbeef"), CharsetClass::Hex);
/// assert_eq!(classify_charset("abc123XYZ"), CharsetClass::Alphanumeric);
/// assert_eq!(classify_charset("abc+/="), CharsetClass::Base64);
/// assert_eq!(classify_charset("hello world!"), CharsetClass::Unknown);
/// ```
#[must_use]
pub fn classify_charset(value: &str) -> CharsetClass {
    if value.is_empty() {
        return CharsetClass::Unknown;
    }

    let mut all_hex = true;
    let mut all_alphanumeric = true;
    let mut all_base64 = true;

    for c in value.chars() {
        if !is_hex_char(c) {
            all_hex = false;
        }
        if !c.is_ascii_alphanumeric() {
            all_alphanumeric = false;
        }
        if !is_base64_char(c) {
            all_base64 = false;
        }

        // Early exit: if nothing matches, it's Unknown
        if !all_hex && !all_alphanumeric && !all_base64 {
            return CharsetClass::Unknown;
        }
    }

    // Return most restrictive match
    if all_hex {
        CharsetClass::Hex
    } else if all_alphanumeric {
        CharsetClass::Alphanumeric
    } else if all_base64 {
        CharsetClass::Base64
    } else {
        CharsetClass::Unknown
    }
}

/// Check if a string consists entirely of Base64 characters
///
/// Base64 charset: `A-Za-z0-9+/=-_` (standard + URL-safe + padding)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::entropy::charsets::is_base64_charset;
///
/// assert!(is_base64_charset("SGVsbG8gV29ybGQ="));
/// assert!(is_base64_charset("abc123-_"));  // URL-safe Base64
/// assert!(!is_base64_charset("hello world!"));
/// ```
#[must_use]
pub fn is_base64_charset(value: &str) -> bool {
    !value.is_empty() && value.chars().all(is_base64_char)
}

/// Check if a string consists entirely of hexadecimal characters
///
/// Hex charset: `0-9a-fA-F`
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::entropy::charsets::is_hex_charset;
///
/// assert!(is_hex_charset("deadbeef"));
/// assert!(is_hex_charset("DEADBEEF"));
/// assert!(is_hex_charset("0123456789abcdef"));
/// assert!(!is_hex_charset("0xDEADBEEF"));  // 'x' is not hex
/// ```
#[must_use]
pub fn is_hex_charset(value: &str) -> bool {
    !value.is_empty() && value.chars().all(is_hex_char)
}

// ============================================================================
// Character Membership Helpers
// ============================================================================

/// Check if a character belongs to the Base64 charset
///
/// Includes standard Base64 (`+`, `/`, `=`) and URL-safe variants (`-`, `_`).
fn is_base64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
}

/// Check if a character belongs to the hexadecimal charset
fn is_hex_char(c: char) -> bool {
    c.is_ascii_hexdigit()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ---- classify_charset ----

    #[test]
    fn test_classify_empty_string() {
        assert_eq!(classify_charset(""), CharsetClass::Unknown);
    }

    #[test]
    fn test_classify_hex_lowercase() {
        assert_eq!(classify_charset("deadbeef"), CharsetClass::Hex);
    }

    #[test]
    fn test_classify_hex_uppercase() {
        assert_eq!(classify_charset("DEADBEEF"), CharsetClass::Hex);
    }

    #[test]
    fn test_classify_hex_mixed_case() {
        assert_eq!(classify_charset("DeAdBeEf"), CharsetClass::Hex);
    }

    #[test]
    fn test_classify_hex_digits_only() {
        // All digits are valid hex — classified as Hex (most restrictive)
        assert_eq!(classify_charset("0123456789"), CharsetClass::Hex);
    }

    #[test]
    fn test_classify_hex_with_digits() {
        assert_eq!(classify_charset("a1b2c3d4e5f6"), CharsetClass::Hex);
    }

    #[test]
    fn test_classify_alphanumeric() {
        // Contains 'g' which is not hex, but is alphanumeric
        assert_eq!(
            classify_charset("abc123XYZghij"),
            CharsetClass::Alphanumeric
        );
    }

    #[test]
    fn test_classify_alphanumeric_letters_only() {
        assert_eq!(classify_charset("HelloWorld"), CharsetClass::Alphanumeric);
    }

    #[test]
    fn test_classify_base64_standard() {
        // Contains '+' and '/' which are Base64 special chars
        assert_eq!(classify_charset("abc+def/ghi="), CharsetClass::Base64);
    }

    #[test]
    fn test_classify_base64_url_safe() {
        // URL-safe Base64 uses '-' and '_'
        assert_eq!(classify_charset("abc-def_ghi"), CharsetClass::Base64);
    }

    #[test]
    fn test_classify_base64_with_padding() {
        assert_eq!(classify_charset("SGVsbG8gV29ybGQ="), CharsetClass::Base64);
    }

    #[test]
    fn test_classify_base64_double_padding() {
        assert_eq!(classify_charset("YQ=="), CharsetClass::Base64);
    }

    #[test]
    fn test_classify_unknown_with_space() {
        assert_eq!(classify_charset("hello world"), CharsetClass::Unknown);
    }

    #[test]
    fn test_classify_unknown_with_special_chars() {
        assert_eq!(classify_charset("hello@world!"), CharsetClass::Unknown);
    }

    #[test]
    fn test_classify_unknown_with_unicode() {
        assert_eq!(classify_charset("héllo"), CharsetClass::Unknown);
    }

    #[test]
    fn test_classify_single_hex_char() {
        assert_eq!(classify_charset("a"), CharsetClass::Hex);
    }

    #[test]
    fn test_classify_single_non_hex_alpha() {
        assert_eq!(classify_charset("g"), CharsetClass::Alphanumeric);
    }

    #[test]
    fn test_classify_single_base64_special() {
        assert_eq!(classify_charset("+"), CharsetClass::Base64);
    }

    // ---- is_base64_charset ----

    #[test]
    fn test_is_base64_charset_valid() {
        assert!(is_base64_charset("SGVsbG8gV29ybGQ="));
        assert!(is_base64_charset("abc123"));
        assert!(is_base64_charset("abc+/="));
        assert!(is_base64_charset("abc-_"));
    }

    #[test]
    fn test_is_base64_charset_invalid() {
        assert!(!is_base64_charset(""));
        assert!(!is_base64_charset("hello world!"));
        assert!(!is_base64_charset("abc@def"));
    }

    // ---- is_hex_charset ----

    #[test]
    fn test_is_hex_charset_valid() {
        assert!(is_hex_charset("deadbeef"));
        assert!(is_hex_charset("DEADBEEF"));
        assert!(is_hex_charset("0123456789abcdef"));
        assert!(is_hex_charset("AaBbCcDdEeFf"));
    }

    #[test]
    fn test_is_hex_charset_invalid() {
        assert!(!is_hex_charset(""));
        assert!(!is_hex_charset("0xDEADBEEF"));
        assert!(!is_hex_charset("ghijkl"));
        assert!(!is_hex_charset("ZZZZ"));
    }

    // ---- CharsetClass traits ----

    #[test]
    fn test_charset_class_debug() {
        let class = CharsetClass::Base64;
        let debug = format!("{:?}", class);
        assert!(debug.contains("Base64"));
    }

    #[test]
    fn test_charset_class_copy() {
        let class = CharsetClass::Hex;
        let copied = class;
        let copied2 = class;
        assert_eq!(copied, copied2);
    }

    #[test]
    fn test_charset_class_eq() {
        assert_eq!(CharsetClass::Base64, CharsetClass::Base64);
        assert_ne!(CharsetClass::Base64, CharsetClass::Hex);
    }
}
