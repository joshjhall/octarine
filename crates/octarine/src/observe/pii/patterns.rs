//! Regex patterns for PII detection and redaction in observe module
//!
//! This module centralizes all regex patterns used for PII scanning and redaction.
//! Patterns are pre-compiled using `once_cell::sync::Lazy` for optimal performance.
//!
//! # Design Principles
//!
//! - **Centralized**: All regex patterns in one place
//! - **Performance**: One-time compilation with Lazy
//! - **Safety**: Module-level allow for expect_used on static patterns
//! - **Maintainability**: Easy to audit and update patterns

// SAFETY: All regex patterns in this module are hardcoded and verified at compile time.
// Regex::new() only fails on invalid syntax, which would be caught during development/testing.
// Using expect() here is safe because these patterns are static and never change at runtime.
//
// NOTE: This module follows the same pattern as security/data/common/identifiers/patterns.rs
// and is explicitly allowed by pre-commit hooks for static pattern compilation.
#![allow(clippy::expect_used)]
#![allow(clippy::panic)] // Required for expect() messages on static patterns

use once_cell::sync::Lazy;
use regex::Regex;

/// Password patterns for detection and redaction
pub mod password {
    use super::*;

    /// Password field pattern (key=value or key: value format)
    /// Captures: (prefix) (value)
    /// Example: "password=secret123" → ("password=", "secret123")
    pub static FIELD_PATTERN: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)(password\s*[:=]\s*)([^\s]+)")
            .expect("BUG: Invalid password regex pattern")
    });
}

/// IP address patterns for detection and redaction
pub mod ip_address {
    use super::*;

    /// IPv4 address pattern (strict validation)
    /// Matches: 0.0.0.0 to 255.255.255.255
    pub static IPV4: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ).expect("BUG: Invalid IPv4 regex pattern")
    });

    /// IPv4 address pattern with capture group for first octet
    /// Captures: (first_octet.)
    /// Example: "192.168.1.1" → ("192.")
    pub static IPV4_WITH_FIRST_OCTET: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"\b((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){2}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ).expect("BUG: Invalid IPv4 regex pattern")
    });
}
