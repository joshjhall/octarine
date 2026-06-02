//! Contact-related network patterns: email, phone, username
//!
//! Patterns for human contact identifiers — email addresses (standard and
//! IP-literal forms), phone numbers (a loose candidate matcher for text
//! scanning plus exact E.164/US patterns for classification), and conservative
//! usernames. Phone *validity* is determined by libphonenumber, not by these
//! regexes — see `primitives/identifiers/personal/detection/phone.rs`.

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

    /// Loose candidate pattern for text scanning.
    ///
    /// Extracts substrings that *might* be phone numbers — an optional `+`,
    /// optional country code, then a run of 7–15 digits with common separators
    /// (spaces, `-`, `.`, parentheses). This is deliberately permissive:
    /// candidates are subsequently parsed and validated by libphonenumber
    /// (`phonenumber::is_valid`), which applies per-region possible-length and
    /// carrier-prefix tables to reject false positives. The pattern therefore
    /// favours recall; precision comes from the validation step.
    ///
    /// Examples: `+1-555-123-4567`, `(415) 867-5309`, `+44 20 7946 0958`,
    /// `+5511987654321`.
    pub static CANDIDATE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\+?\(?\d(?:[\d\s().\-]{5,20}\d)?").expect("BUG: Invalid regex pattern")
    });

    /// E.164 format (exact match for validation)
    /// Example: "+15551234567"
    pub static E164_EXACT: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\+[1-9]\d{1,14}$").expect("BUG: Invalid regex pattern"));

    /// US phone exact match (for lenient classification)
    /// Example: "(555) 123-4567", "555-123-4567"
    pub static US_EXACT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^(\+1[-.\s]?)?(\([0-9]{3}\)|[0-9]{3})[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$")
            .expect("BUG: Invalid regex pattern")
    });
}

pub(crate) mod username {
    use super::*;

    /// Standard username pattern (alphanumeric with underscore, dot, dash)
    /// Example: "john_doe", "user.name", "test-user"
    pub static STANDARD: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_.-]{3,32}$").expect("BUG: Invalid regex pattern"));
}
