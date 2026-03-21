//! LDAP injection detection
//!
//! Detection functions for identifying LDAP injection patterns (RFC 4515, RFC 4514).
//!
//! # Attack Vectors
//!
//! | Vector | Description | CWE |
//! |--------|-------------|-----|
//! | Filter injection | Modifying filter logic | CWE-90 |
//! | Null byte | String truncation | CWE-158 |
//! | Wildcard abuse | Directory enumeration | CWE-90 |
//!
//! # LDAP Filter Syntax (RFC 4515)
//!
//! ```text
//! filter     = "(" filtercomp ")"
//! filtercomp = and / or / not / simple
//! and        = "&" filterlist
//! or         = "|" filterlist
//! not        = "!" filter
//! simple     = attr filtertype value
//! filtertype = "=" / "~=" / ">=" / "<=" / "*"
//! ```

use super::patterns;
use crate::primitives::security::queries::types::QueryThreat;

/// Check if input contains any LDAP injection patterns
///
/// This is a comprehensive check that looks for multiple attack vectors.
///
/// # Arguments
///
/// * `input` - The string to check for injection patterns
///
/// # Returns
///
/// `true` if any injection pattern is detected
#[must_use]
pub fn is_ldap_injection_present(input: &str) -> bool {
    if input.is_empty() {
        return false;
    }

    patterns::is_ldap_filter_chars_present(input)
        || patterns::is_null_bytes_present(input)
        || patterns::is_filter_breakout_present(input)
}

/// Detect all LDAP injection threats in input
///
/// Returns a list of all detected threat types for logging/analysis.
///
/// # Arguments
///
/// * `input` - The string to analyze for injection patterns
///
/// # Returns
///
/// Vector of all detected threat types
#[must_use]
pub fn detect_ldap_threats(input: &str) -> Vec<QueryThreat> {
    let mut threats = Vec::new();

    if input.is_empty() {
        return threats;
    }

    // Filter injection - special characters that modify filter logic
    if patterns::is_ldap_filter_chars_present(input) || patterns::is_filter_breakout_present(input)
    {
        threats.push(QueryThreat::LdapFilterInjection);
    }

    // Null byte injection - string truncation attacks
    if patterns::is_null_bytes_present(input) {
        threats.push(QueryThreat::LdapNullByte);
    }

    // Wildcard abuse - enumeration attacks
    if input.contains('*') && !input.starts_with('*') && !input.ends_with('*') {
        // Interior wildcards are more suspicious
        threats.push(QueryThreat::LdapWildcard);
    } else if input == "*" {
        // Standalone wildcard for enumeration
        threats.push(QueryThreat::LdapWildcard);
    }

    threats
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ldap_injection_present_filter_chars() {
        assert!(is_ldap_injection_present("admin)("));
        assert!(is_ldap_injection_present("test*"));
        assert!(is_ldap_injection_present("(uid=*)"));
        assert!(is_ldap_injection_present("user|admin"));
        assert!(is_ldap_injection_present("user&admin"));
    }

    #[test]
    fn test_is_ldap_injection_present_null_byte() {
        assert!(is_ldap_injection_present("admin\0"));
        assert!(is_ldap_injection_present("user\0suffix"));
    }

    #[test]
    fn test_is_ldap_injection_present_safe() {
        assert!(!is_ldap_injection_present("admin"));
        assert!(!is_ldap_injection_present("john.doe"));
        assert!(!is_ldap_injection_present("user@example.com"));
        assert!(!is_ldap_injection_present(""));
    }

    #[test]
    fn test_detect_ldap_threats_comprehensive() {
        // Filter injection
        let threats = detect_ldap_threats("admin)(");
        assert!(threats.contains(&QueryThreat::LdapFilterInjection));

        // Null byte
        let threats = detect_ldap_threats("admin\0");
        assert!(threats.contains(&QueryThreat::LdapNullByte));

        // Wildcard enumeration (standalone)
        let threats = detect_ldap_threats("*");
        assert!(threats.contains(&QueryThreat::LdapWildcard));
    }

    #[test]
    fn test_detect_ldap_threats_empty() {
        let threats = detect_ldap_threats("");
        assert!(threats.is_empty());
    }

    #[test]
    fn test_common_ldap_payloads() {
        // Filter breakout attacks
        assert!(is_ldap_injection_present("*)(uid=*))(|(uid=*"));
        assert!(is_ldap_injection_present("admin)(|(password=*"));

        // OR/AND injection
        assert!(is_ldap_injection_present(")(|(objectclass=*"));
        assert!(is_ldap_injection_present(")(&(uid=admin)(password="));

        // Null byte termination
        assert!(is_ldap_injection_present("admin\0(anything)"));
    }
}
