// SAFETY: All expect() calls in this module are on regex patterns that are
// guaranteed to compile (simple fallback patterns like r"^$").
#![allow(clippy::expect_used)]

//! LDAP injection detection patterns
//!
//! Patterns for detecting LDAP injection attacks following RFC 4515 and RFC 4514.
//!
//! # RFC 4515: LDAP Filter Syntax
//!
//! Special characters that must be escaped in filter values:
//! - `*` (0x2a) - Wildcard
//! - `(` (0x28) - Filter open
//! - `)` (0x29) - Filter close
//! - `\` (0x5c) - Escape character
//! - NUL (0x00) - String terminator
//!
//! # RFC 4514: DN Syntax
//!
//! Special characters in Distinguished Names:
//! - `,` - RDN separator
//! - `+` - Multi-valued RDN
//! - `=` - Attribute/value separator
//! - `"` - Quoted string delimiter
//! - `\` - Escape character
//! - `<` `>` `;` - Special meaning in certain contexts

use once_cell::sync::Lazy;
use regex::Regex;

// ============================================================================
// Constants
// ============================================================================

/// LDAP special characters that need escaping (RFC 4515)
pub const LDAP_FILTER_ESCAPE_CHARS: &[(char, &str)] = &[
    ('\\', "\\5c"),
    ('*', "\\2a"),
    ('(', "\\28"),
    (')', "\\29"),
    ('\0', "\\00"),
];

/// LDAP DN special characters that need escaping (RFC 4514)
pub const LDAP_DN_ESCAPE_CHARS: &[(char, &str)] = &[
    ('\\', "\\\\"),
    (',', "\\,"),
    ('+', "\\+"),
    ('"', "\\\""),
    ('<', "\\<"),
    ('>', "\\>"),
    (';', "\\;"),
    ('=', "\\="),
];

/// LDAP filter operators
pub const LDAP_FILTER_OPERATORS: &[char] = &['(', ')', '|', '&', '!', '*', '~', '='];

// ============================================================================
// Compiled Patterns
// ============================================================================

/// Helper to create fallback regex
fn fallback_regex() -> Regex {
    Regex::new(r"^$").expect("fallback regex should compile")
}

/// Pattern for detecting LDAP filter special characters
pub static LDAP_FILTER_INJECTION_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[)(|&*]").unwrap_or_else(|_| fallback_regex()));

/// Pattern for detecting filter breakout sequences
pub static FILTER_BREAKOUT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    // Matches sequences that break out of filter context
    // e.g., ")(" , ")(|" , ")(&" , ")(!
    Regex::new(r"\)\s*[\(&|!]|\)\s*\(").unwrap_or_else(|_| fallback_regex())
});

/// Pattern for detecting null bytes
pub static NULL_BYTE_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\x00").unwrap_or_else(|_| fallback_regex()));

/// Pattern for detecting OR/AND injection
pub static LOGICAL_INJECTION_PATTERN: Lazy<Regex> = Lazy::new(|| {
    // Matches |( or &( which could inject additional conditions
    Regex::new(r"[|&]\s*\(").unwrap_or_else(|_| fallback_regex())
});

// ============================================================================
// Detection Functions
// ============================================================================

/// Check if input contains LDAP filter special characters
#[must_use]
pub fn is_ldap_filter_chars_present(input: &str) -> bool {
    LDAP_FILTER_INJECTION_PATTERN.is_match(input)
}

/// Check if input contains null bytes
#[must_use]
pub fn is_null_bytes_present(input: &str) -> bool {
    input.contains('\0')
}

/// Check if input contains filter breakout sequences
#[must_use]
pub fn is_filter_breakout_present(input: &str) -> bool {
    FILTER_BREAKOUT_PATTERN.is_match(input) || LOGICAL_INJECTION_PATTERN.is_match(input)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_chars_detection() {
        assert!(is_ldap_filter_chars_present("admin)"));
        assert!(is_ldap_filter_chars_present("(uid=admin"));
        assert!(is_ldap_filter_chars_present("test*"));
        assert!(is_ldap_filter_chars_present("user|admin"));
        assert!(is_ldap_filter_chars_present("user&admin"));

        assert!(!is_ldap_filter_chars_present("admin"));
        assert!(!is_ldap_filter_chars_present("john.doe"));
    }

    #[test]
    fn test_null_byte_detection() {
        assert!(is_null_bytes_present("admin\0"));
        assert!(is_null_bytes_present("\0"));
        assert!(is_null_bytes_present("user\0suffix"));

        assert!(!is_null_bytes_present("admin"));
        assert!(!is_null_bytes_present(""));
    }

    #[test]
    fn test_filter_breakout_detection() {
        assert!(is_filter_breakout_present(")("));
        assert!(is_filter_breakout_present(")(|"));
        assert!(is_filter_breakout_present(")(&"));
        assert!(is_filter_breakout_present(") ("));
        assert!(is_filter_breakout_present("|(objectclass=*"));
        assert!(is_filter_breakout_present("&(uid=admin"));

        assert!(!is_filter_breakout_present("admin"));
        assert!(!is_filter_breakout_present("user.name"));
    }

    #[test]
    fn test_common_ldap_injection_patterns() {
        // Classic filter breakout
        assert!(is_filter_breakout_present("*)(uid=*))(|(uid=*"));

        // OR injection
        assert!(is_filter_breakout_present(")(|(password=*"));

        // AND injection
        assert!(is_filter_breakout_present(")(&(uid=admin)(password="));
    }
}
