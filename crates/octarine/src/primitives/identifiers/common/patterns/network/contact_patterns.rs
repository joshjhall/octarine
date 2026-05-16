//! Contact-related network patterns: email, phone, username
//!
//! Patterns for human contact identifiers — email addresses (standard and
//! IP-literal forms), phone numbers (US plus 9 country-specific formats and
//! E.164), and conservative usernames.

#![allow(clippy::expect_used)]
// SAFETY: All regex patterns in this module are hardcoded and verified at compile time.

use once_cell::sync::Lazy;
use regex::Regex;

pub(crate) mod email {
    use super::*;

    /// Standard email pattern (for text scanning)
    /// Example: "user@example.com"
    pub static STANDARD: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Exact email pattern (for validation)
    /// Example: "user@example.com"
    pub static EXACT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\])$")
            .expect("BUG: Invalid regex pattern")
    });

    /// IP literal email pattern (for text scanning)
    /// Example: "user@[192.168.1.1]"
    pub static IP_LITERAL: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"[A-Za-z0-9._%+-]+@\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]")
            .expect("BUG: Invalid regex pattern")
    });

    /// All email patterns in this submodule — standard `user@domain.tld` and IP-literal `user@[1.2.3.4]`.
    pub fn all() -> Vec<&'static Regex> {
        vec![&*STANDARD, &*IP_LITERAL]
    }
}
pub(crate) mod phone {
    use super::*;

    /// US phone with country code
    /// Example: "+1-555-123-4567"
    pub static WITH_COUNTRY_CODE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\+1[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")
            .expect("BUG: Invalid regex pattern")
    });

    /// US phone with parentheses
    /// Example: "(555) 123-4567"
    pub static WITH_PARENS: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\(\d{3}\)\s*\d{3}[-.\s]?\d{4}").expect("BUG: Invalid regex pattern")
    });

    /// US phone standard format
    /// Example: "555-123-4567"
    pub static STANDARD: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b").expect("BUG: Invalid regex pattern")
    });

    /// International format (generic 10+ digits with optional +)
    /// Example: "+44 20 7946 0958"
    pub static INTERNATIONAL: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\+?\d{1,3}[-.\s]?\d{1,14}").expect("BUG: Invalid regex pattern"));

    // ── Country-specific patterns for text scanning ────────────────────

    /// UK phone: +44 followed by 10 digits (mobile or landline)
    /// Examples: "+44 7911 123456", "+447911123456", "+44 20 7946 0958"
    pub static UK: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\+44[-.\s]?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}")
            .expect("BUG: Invalid regex pattern")
    });

    /// German phone: +49 followed by 10-11 digits
    /// Examples: "+49 30 12345678", "+49 170 1234567", "+4930123456"
    pub static DE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\+49[-.\s]?\d{2,4}[-.\s]?\d{3,8}[-.\s]?\d{0,4}")
            .expect("BUG: Invalid regex pattern")
    });

    /// French phone: +33 followed by 9 digits
    /// Examples: "+33 1 23 45 67 89", "+33123456789"
    pub static FR: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\+33[-.\s]?\d[-.\s]?\d{2}[-.\s]?\d{2}[-.\s]?\d{2}[-.\s]?\d{2}")
            .expect("BUG: Invalid regex pattern")
    });

    /// Australian phone: +61 followed by 9 digits
    /// Examples: "+61 4 1234 5678", "+61412345678"
    pub static AU: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\+61[-.\s]?\d[-.\s]?\d{4}[-.\s]?\d{4}").expect("BUG: Invalid regex pattern")
    });

    /// Indian phone: +91 followed by 10 digits (mobile starts with 6-9)
    /// Examples: "+91 98765 43210", "+919876543210"
    pub static IN_: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\+91[-.\s]?[6-9]\d{4}[-.\s]?\d{5}").expect("BUG: Invalid regex pattern")
    });

    /// Japanese phone: +81 followed by 9-10 digits
    /// Examples: "+81 3 1234 5678", "+81 90 1234 5678"
    pub static JP: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\+81[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{4}")
            .expect("BUG: Invalid regex pattern")
    });

    /// Brazilian phone: +55 followed by 10-11 digits (area + number)
    /// Examples: "+55 11 98765 4321", "+5511987654321"
    pub static BR: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\+55[-.\s]?\d{2}[-.\s]?\d{4,5}[-.\s]?\d{4}")
            .expect("BUG: Invalid regex pattern")
    });

    /// Chinese phone: +86 followed by 11 digits (mobile starts 1[3-9])
    /// Examples: "+86 138 1234 5678", "+8613812345678"
    pub static CN: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\+86[-.\s]?1[3-9]\d[-.\s]?\d{4}[-.\s]?\d{4}")
            .expect("BUG: Invalid regex pattern")
    });

    /// E.164 text scanning: any + followed by 7-15 digits (no separators)
    /// Example: "+442071234567", "+5511987654321"
    pub static E164_TEXT: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\+[1-9]\d{6,14}").expect("BUG: Invalid regex pattern"));

    /// E.164 format (exact match for validation)
    /// Example: "+15551234567"
    pub static E164_EXACT: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\+[1-9]\d{1,14}$").expect("BUG: Invalid regex pattern"));

    /// US phone exact match (for validation)
    /// Example: "(555) 123-4567", "555-123-4567"
    pub static US_EXACT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^(\+1[-.\s]?)?(\([0-9]{3}\)|[0-9]{3})[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$")
            .expect("BUG: Invalid regex pattern")
    });

    /// All phone patterns in this submodule — US formats (with country code,
    /// parens, or plain) plus country-specific patterns for UK, DE, FR, AU,
    /// IN, JP, BR, CN, and a generic E.164 text-scanning fallback.
    pub fn all() -> Vec<&'static Regex> {
        vec![
            &*WITH_COUNTRY_CODE,
            &*WITH_PARENS,
            &*STANDARD,
            &*UK,
            &*DE,
            &*FR,
            &*AU,
            &*IN_,
            &*JP,
            &*BR,
            &*CN,
            &*E164_TEXT,
        ]
    }
}

pub(crate) mod username {
    use super::*;

    /// Standard username pattern (alphanumeric with underscore, dot, dash)
    /// Example: "john_doe", "user.name", "test-user"
    pub static STANDARD: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_.-]{3,32}$").expect("BUG: Invalid regex pattern"));
}
