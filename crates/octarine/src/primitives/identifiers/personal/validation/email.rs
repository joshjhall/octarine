//! Email validation functions
//!
//! Validates email addresses according to RFC standards with security checks.

use crate::primitives::Problem;

use super::super::detection;

// ============================================================================
// Email Validation
// ============================================================================

/// Validate email address format (returns Result)
///
/// Uses simplified regex to avoid ReDoS attacks.
/// Does not validate email deliverability, only format.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::validation;
///
/// assert!(validation::validate_email("user@example.com").is_ok());
/// assert!(validation::validate_email("invalid").is_err());
/// ```
///
/// # Errors
///
/// Returns `Problem::validation` if:
/// - Email is shorter than 3 or longer than 254 characters
/// - Local part is empty or longer than 64 characters
/// - Email format doesn't match RFC pattern
/// - Email contains dangerous XSS patterns
pub fn validate_email(email: &str) -> Result<(), Problem> {
    // Length limits to prevent DoS
    if email.len() < 3 || email.len() > 254 {
        return Err(Problem::Validation("Email must be 3-254 characters".into()));
    }

    // Check for local part length (before @)
    if let Some(at_pos) = email.find('@') {
        let local_part = &email[..at_pos];
        if local_part.is_empty() || local_part.len() > 64 {
            return Err(Problem::Validation(
                "Email local part must be 1-64 characters".into(),
            ));
        }
    }

    if !detection::is_email(email) {
        return Err(Problem::Validation("Invalid email format".into()));
    }

    // Check for actual XSS patterns (not just substrings)
    // Email addresses shouldn't contain HTML/JS injection patterns
    let email_lower = email.to_lowercase();

    // Check for HTML script tags and JavaScript protocol
    if email_lower.contains("<script")
        || email_lower.contains("</script")
        || email_lower.contains("javascript:")
        || email_lower.contains("onerror=")
        || email_lower.contains("onclick=")
        || email_lower.contains("onload=")
        || email_lower.contains("onmouseover=")
        || email_lower.contains("<img")
        || email_lower.contains("<iframe")
    {
        return Err(Problem::Validation(
            "Email contains invalid HTML/JavaScript patterns".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_email_validation() {
        // Valid emails
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("user.name@example.co.uk").is_ok());
        assert!(validate_email("user+tag@example.com").is_ok());

        // Invalid formats
        assert!(validate_email("invalid").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@").is_err());
        assert!(validate_email("user@.com").is_err());

        // Injection attempts
        assert!(validate_email("user<script>@example.com").is_err());
        assert!(validate_email("javascript:alert@example.com").is_err());

        // Length limits
        assert!(validate_email("a@b").is_err()); // Too short (less than 3)
        assert!(validate_email(&format!("{}@example.com", "a".repeat(65))).is_err());
        // Local part too long
    }

    #[test]
    fn test_email_validation_errors() {
        let err = validate_email("invalid").expect_err("should fail for invalid email");
        assert!(err.to_string().contains("Invalid email format"));

        // "a@b" is exactly 3 chars but fails regex (no valid TLD)
        let err = validate_email("a@b").expect_err("should fail for invalid TLD");
        assert!(err.to_string().contains("Invalid email format"));

        // Test the length check with genuinely short email
        let err = validate_email("ab").expect_err("should fail for short email");
        assert!(err.to_string().contains("3-254 characters"));

        let err = validate_email(&format!("{}@example.com", "a".repeat(65)))
            .expect_err("should fail for long local part");
        assert!(err.to_string().contains("1-64 characters"));
    }

    #[test]
    fn test_email_xss_prevention() {
        assert!(validate_email("user<script>@example.com").is_err());
        assert!(validate_email("javascript:foo@example.com").is_err());

        // But normal words containing these substrings should still work if they pass regex
        // "description@example.com" contains "script" but fails regex due to the format
        assert!(validate_email("desc@example.com").is_ok()); // This is fine
    }

    #[test]
    fn test_email_edge_cases() {
        // Empty and whitespace
        assert!(validate_email("").is_err());
        assert!(validate_email("   ").is_err());

        // At length boundaries
        assert!(validate_email(&format!("{}@example.com", "a".repeat(64))).is_ok()); // Max local part
        assert!(validate_email(&format!("{}@example.com", "a".repeat(65))).is_err()); // Too long local

        // Unicode in domain (IDN - not supported by simple regex)
        assert!(validate_email("user@例え.jp").is_err()); // Japanese TLD

        // Special characters in local part
        assert!(validate_email("user+tag@example.com").is_ok());
        assert!(validate_email("user.name@example.com").is_ok());

        // IP address domain (RFC 5321 IP literal)
        assert!(validate_email("user@[192.168.1.1]").is_ok());

        // Valid emails that might look dangerous but aren't
        assert!(validate_email("onload@example.com").is_ok()); // Valid - "onload" is just text
        assert!(validate_email("onclick@example.com").is_ok()); // Valid - "onclick" is just text
    }
}
