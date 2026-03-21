//! Custom Predicates for Security Testing
//!
//! Provides predicates that can be used with the `predicates` crate
//! for matching security patterns.

use predicates::prelude::*;
use predicates::reflection::{Case, PredicateReflection};
use std::fmt;

// ============================================================================
// Path Safety Predicates
// ============================================================================

/// Predicate that checks if a path is safe (no traversal)
#[derive(Debug, Clone, Copy)]
pub struct SafePathPredicate;

impl fmt::Display for SafePathPredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "is a safe path (no traversal)")
    }
}

impl PredicateReflection for SafePathPredicate {}

impl Predicate<str> for SafePathPredicate {
    fn eval(&self, variable: &str) -> bool {
        let lower = variable.to_lowercase();
        !lower.contains("..")
            && !lower.contains("%2e%2e")
            && !lower.contains("%252e")
            && !variable.contains('\0')
    }

    fn find_case<'a>(&'a self, expected: bool, variable: &str) -> Option<Case<'a>> {
        if self.eval(variable) == expected {
            Some(Case::new(Some(self), expected))
        } else {
            None
        }
    }
}

/// Create a predicate that checks for safe paths
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::assertions::predicates::is_safe_path;
/// use predicates::prelude::*;
///
/// let pred = is_safe_path();
/// assert!(pred.eval("/normal/path.txt"));
/// assert!(!pred.eval("../etc/passwd"));
/// ```
pub fn is_safe_path() -> SafePathPredicate {
    SafePathPredicate
}

// ============================================================================
// Command Injection Predicates
// ============================================================================

/// Predicate that checks if input is free of command injection
#[derive(Debug, Clone, Copy)]
pub struct NoCommandInjectionPredicate;

impl fmt::Display for NoCommandInjectionPredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "contains no command injection patterns")
    }
}

impl PredicateReflection for NoCommandInjectionPredicate {}

impl Predicate<str> for NoCommandInjectionPredicate {
    fn eval(&self, variable: &str) -> bool {
        !variable.contains("$(")
            && !variable.contains("${")
            && !variable.contains('`')
            && !variable.contains(';')
            && !variable.contains('|')
            && !variable.contains("&&")
            && !variable.contains("||")
            && !variable.contains('\n')
            && !variable.contains('\r')
    }

    fn find_case<'a>(&'a self, expected: bool, variable: &str) -> Option<Case<'a>> {
        if self.eval(variable) == expected {
            Some(Case::new(Some(self), expected))
        } else {
            None
        }
    }
}

/// Create a predicate that checks for command injection
pub fn no_command_injection() -> NoCommandInjectionPredicate {
    NoCommandInjectionPredicate
}

// ============================================================================
// PII Detection Predicates
// ============================================================================

/// Predicate that checks if content is properly redacted
#[derive(Debug, Clone)]
pub struct IsRedactedPredicate {
    patterns: Vec<regex::Regex>,
}

impl Default for IsRedactedPredicate {
    fn default() -> Self {
        Self::new()
    }
}

impl IsRedactedPredicate {
    /// Create a new redaction predicate with default PII patterns
    pub fn new() -> Self {
        Self {
            patterns: vec![
                // SSN
                regex::Regex::new(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b")
                    .expect("Invalid SSN regex pattern"),
                // Email
                regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
                    .expect("Invalid email regex pattern"),
                // Credit card
                regex::Regex::new(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")
                    .expect("Invalid credit card regex pattern"),
                // Phone (US)
                regex::Regex::new(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b")
                    .expect("Invalid phone regex pattern"),
            ],
        }
    }
}

impl fmt::Display for IsRedactedPredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "is properly redacted (no PII patterns)")
    }
}

impl PredicateReflection for IsRedactedPredicate {}

impl Predicate<str> for IsRedactedPredicate {
    fn eval(&self, variable: &str) -> bool {
        // Should not match any PII patterns
        !self.patterns.iter().any(|p| p.is_match(variable))
    }

    fn find_case<'a>(&'a self, expected: bool, variable: &str) -> Option<Case<'a>> {
        if self.eval(variable) == expected {
            Some(Case::new(Some(self), expected))
        } else {
            None
        }
    }
}

/// Create a predicate that checks content is redacted
pub fn is_redacted() -> IsRedactedPredicate {
    IsRedactedPredicate::new()
}

// ============================================================================
// URL Safety Predicates
// ============================================================================

/// Predicate that checks if a URL is safe (no SSRF)
#[derive(Debug, Clone, Copy)]
pub struct SafeUrlPredicate;

impl fmt::Display for SafeUrlPredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "is a safe URL (no SSRF patterns)")
    }
}

impl PredicateReflection for SafeUrlPredicate {}

impl Predicate<str> for SafeUrlPredicate {
    fn eval(&self, variable: &str) -> bool {
        let lower = variable.to_lowercase();

        // Check for dangerous patterns
        let dangerous = [
            "169.254.169.254",
            "metadata.google",
            "localhost",
            "127.0.0.1",
            "[::1]",
            "0.0.0.0",
            "file://",
            "gopher://",
            "dict://",
        ];

        // Check private network ranges
        let private_ranges = ["10.", "192.168.", "172.16.", "172.17.", "172.18."];

        !dangerous.iter().any(|p| lower.contains(p))
            && !private_ranges.iter().any(|p| lower.contains(p))
    }

    fn find_case<'a>(&'a self, expected: bool, variable: &str) -> Option<Case<'a>> {
        if self.eval(variable) == expected {
            Some(Case::new(Some(self), expected))
        } else {
            None
        }
    }
}

/// Create a predicate that checks for safe URLs
pub fn is_safe_url() -> SafeUrlPredicate {
    SafeUrlPredicate
}

// ============================================================================
// Log Safety Predicates
// ============================================================================

/// Predicate that checks if log output is safe
#[derive(Debug, Clone, Copy)]
pub struct SafeLogOutputPredicate;

impl fmt::Display for SafeLogOutputPredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "is safe log output (no injection)")
    }
}

impl PredicateReflection for SafeLogOutputPredicate {}

impl Predicate<str> for SafeLogOutputPredicate {
    fn eval(&self, variable: &str) -> bool {
        !variable.contains("\n[")
            && !variable.contains("\r\n[")
            && !variable.contains("\x1b[")
            && !variable.contains("\x1b]")
            && !variable.contains("\u{202E}")
    }

    fn find_case<'a>(&'a self, expected: bool, variable: &str) -> Option<Case<'a>> {
        if self.eval(variable) == expected {
            Some(Case::new(Some(self), expected))
        } else {
            None
        }
    }
}

/// Create a predicate that checks for safe log output
pub fn is_safe_log_output() -> SafeLogOutputPredicate {
    SafeLogOutputPredicate
}

// ============================================================================
// Identifier Predicates
// ============================================================================

/// Predicate that checks if a string is a valid identifier format
#[derive(Debug, Clone)]
pub struct ValidIdentifierPredicate {
    pattern: regex::Regex,
}

impl ValidIdentifierPredicate {
    /// Create a new identifier predicate with a custom regex pattern
    pub fn new(pattern: &str) -> Self {
        Self {
            pattern: regex::Regex::new(pattern).expect("Invalid regex pattern"),
        }
    }

    /// UUID format
    pub fn uuid() -> Self {
        Self::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    }

    /// Slug format (lowercase alphanumeric with hyphens)
    pub fn slug() -> Self {
        Self::new(r"^[a-z][a-z0-9-]*[a-z0-9]$")
    }

    /// Username format
    pub fn username() -> Self {
        Self::new(r"^[a-zA-Z][a-zA-Z0-9_]{2,29}$")
    }
}

impl fmt::Display for ValidIdentifierPredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "matches identifier pattern: {}", self.pattern)
    }
}

impl PredicateReflection for ValidIdentifierPredicate {}

impl Predicate<str> for ValidIdentifierPredicate {
    fn eval(&self, variable: &str) -> bool {
        self.pattern.is_match(variable)
    }

    fn find_case<'a>(&'a self, expected: bool, variable: &str) -> Option<Case<'a>> {
        if self.eval(variable) == expected {
            Some(Case::new(Some(self), expected))
        } else {
            None
        }
    }
}

/// Create a UUID format predicate
pub fn is_valid_uuid() -> ValidIdentifierPredicate {
    ValidIdentifierPredicate::uuid()
}

/// Create a slug format predicate
pub fn is_valid_slug() -> ValidIdentifierPredicate {
    ValidIdentifierPredicate::slug()
}

/// Create a username format predicate
pub fn is_valid_username() -> ValidIdentifierPredicate {
    ValidIdentifierPredicate::username()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_safe_path_predicate() {
        let pred = is_safe_path();
        assert!(pred.eval("/normal/path.txt"));
        assert!(pred.eval("file.txt"));
        assert!(!pred.eval("../etc/passwd"));
        assert!(!pred.eval("path%2e%2e/file"));
    }

    #[test]
    fn test_no_command_injection_predicate() {
        let pred = no_command_injection();
        assert!(pred.eval("normal_input"));
        assert!(!pred.eval("$(whoami)"));
        assert!(!pred.eval("cmd; rm -rf /"));
    }

    #[test]
    fn test_is_redacted_predicate() {
        let pred = is_redacted();
        assert!(pred.eval("User ID: [SSN]"));
        assert!(pred.eval("Email: [REDACTED]"));
        assert!(!pred.eval("SSN: 123-45-6789"));
        assert!(!pred.eval("Email: test@example.com"));
    }

    #[test]
    fn test_safe_url_predicate() {
        let pred = is_safe_url();
        assert!(pred.eval("https://example.com/api"));
        assert!(!pred.eval("http://169.254.169.254/"));
        assert!(!pred.eval("http://localhost/admin"));
        assert!(!pred.eval("file:///etc/passwd"));
    }

    #[test]
    fn test_safe_log_output_predicate() {
        let pred = is_safe_log_output();
        assert!(pred.eval("Normal log message"));
        assert!(!pred.eval("Message\n[ERROR] Fake"));
        assert!(!pred.eval("Color\x1b[31mRed"));
    }

    #[test]
    fn test_valid_uuid_predicate() {
        let pred = is_valid_uuid();
        assert!(pred.eval("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!pred.eval("not-a-uuid"));
        assert!(!pred.eval("550e8400-e29b-41d4-a716-4466554400")); // Too short
    }

    #[test]
    fn test_valid_slug_predicate() {
        let pred = is_valid_slug();
        assert!(pred.eval("my-article-title"));
        assert!(pred.eval("post-123"));
        assert!(!pred.eval("My-Article")); // Uppercase
        assert!(!pred.eval("-leading")); // Leading hyphen
    }

    #[test]
    fn test_valid_username_predicate() {
        let pred = is_valid_username();
        assert!(pred.eval("john_doe"));
        assert!(pred.eval("Alice123"));
        assert!(!pred.eval("1user")); // Starts with number
        assert!(!pred.eval("ab")); // Too short
    }
}
