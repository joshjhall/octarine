// Allow arithmetic - string capacity estimation is safe
#![allow(clippy::arithmetic_side_effects)]

//! LDAP escaping and sanitization
//!
//! Functions for escaping LDAP filters and distinguished names.
//! Implements RFC 4515 (filter escaping) and RFC 4514 (DN escaping).

use super::patterns::{LDAP_DN_ESCAPE_CHARS, LDAP_FILTER_ESCAPE_CHARS};

/// Escape a string for use in LDAP filters (RFC 4515)
///
/// # Arguments
///
/// * `input` - The string to escape
///
/// # Returns
///
/// The escaped string safe for LDAP filter interpolation
#[must_use]
pub fn escape_ldap_filter(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 2);

    for c in input.chars() {
        let mut escaped = false;
        for (escape_char, replacement) in LDAP_FILTER_ESCAPE_CHARS {
            if c == *escape_char {
                result.push_str(replacement);
                escaped = true;
                break;
            }
        }
        if !escaped {
            // Also escape non-ASCII and control characters
            if c.is_ascii_control() || !c.is_ascii() {
                for byte in c.to_string().bytes() {
                    result.push_str(&format!("\\{byte:02x}"));
                }
            } else {
                result.push(c);
            }
        }
    }

    result
}

/// Escape a string for use in LDAP distinguished names (RFC 4514)
///
/// # Arguments
///
/// * `input` - The string to escape
///
/// # Returns
///
/// The escaped string safe for LDAP DN interpolation
#[must_use]
pub fn escape_ldap_dn(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 2);

    for (i, c) in input.chars().enumerate() {
        // Escape leading/trailing spaces
        if (i == 0 || i == input.len().saturating_sub(1)) && c == ' ' {
            result.push_str("\\ ");
            continue;
        }

        // Escape leading #
        if i == 0 && c == '#' {
            result.push_str("\\#");
            continue;
        }

        let mut escaped = false;
        for (escape_char, replacement) in LDAP_DN_ESCAPE_CHARS {
            if c == *escape_char {
                result.push_str(replacement);
                escaped = true;
                break;
            }
        }
        if !escaped {
            result.push(c);
        }
    }

    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_ldap_filter_basic() {
        assert_eq!(escape_ldap_filter("hello"), "hello");
        assert_eq!(escape_ldap_filter("test*"), "test\\2a");
        assert_eq!(escape_ldap_filter("(admin)"), "\\28admin\\29");
        assert_eq!(escape_ldap_filter("user\\name"), "user\\5cname");
    }

    #[test]
    fn test_escape_ldap_filter_null() {
        assert_eq!(escape_ldap_filter("test\0null"), "test\\00null");
    }

    #[test]
    fn test_escape_ldap_dn_basic() {
        assert_eq!(escape_ldap_dn("hello"), "hello");
        assert_eq!(escape_ldap_dn("user,name"), "user\\,name");
        assert_eq!(escape_ldap_dn("test+value"), "test\\+value");
    }

    #[test]
    fn test_escape_ldap_dn_leading_hash() {
        assert_eq!(escape_ldap_dn("#comment"), "\\#comment");
    }

    #[test]
    fn test_escape_ldap_dn_spaces() {
        assert_eq!(escape_ldap_dn(" leading"), "\\ leading");
        assert_eq!(escape_ldap_dn("trailing "), "trailing\\ ");
    }
}
