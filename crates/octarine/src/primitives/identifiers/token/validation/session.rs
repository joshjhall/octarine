//! Session validation functions
//!
//! Pure validation functions for token identifiers.

use super::super::super::common::patterns;
use super::super::detection::is_likely_session_id;
use crate::primitives::Problem;

// ============================================================================
// Session ID Validation
// ============================================================================

/// Validate session ID format (strict - returns Result)
pub fn validate_session_id(
    session_id: &str,
    min_length: usize,
    max_length: usize,
) -> Result<(), Problem> {
    // Use detection layer first
    if !is_likely_session_id(session_id) {
        return Err(Problem::Validation("Invalid session ID format".into()));
    }

    // Length validation
    if session_id.len() < min_length {
        return Err(Problem::Validation(format!(
            "Session ID too short (minimum {} characters)",
            min_length
        )));
    }

    if session_id.len() > max_length {
        return Err(Problem::Validation(format!(
            "Session ID too long (maximum {} characters)",
            max_length
        )));
    }

    // Check for predictable patterns (OWASP A02:2021 - Cryptographic Failures)
    let session_lower = session_id.to_lowercase();

    // Sequential patterns
    if session_lower.contains("12345")
        || session_lower.contains("abcdef")
        || session_lower.contains("00000")
    {
        return Err(Problem::Validation(
            "Session ID contains predictable pattern".into(),
        ));
    }

    // Test/demo patterns
    if session_lower.contains("test") || session_lower.contains("demo") {
        return Err(Problem::Validation(
            "Test/demo session IDs not allowed".into(),
        ));
    }

    // Check character set (should be alphanumeric + hyphens/underscores)
    if !session_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Problem::Validation(
            "Session ID contains invalid characters".into(),
        ));
    }

    Ok(())
}

// ============================================================================
#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_adversarial_session_id_predictable() {
        // Predictable patterns should fail
        assert!(validate_session_id("12345678901234567890", 16, 64).is_err());
        assert!(validate_session_id("abcdefghijklmnopqrst", 16, 64).is_err());
        assert!(validate_session_id("00000000000000000000", 16, 64).is_err());

        // Test/demo patterns
        assert!(validate_session_id("test_session_12345678", 16, 64).is_err());
        assert!(validate_session_id("demo_session_12345678", 16, 64).is_err());
    }

    #[test]
    fn test_adversarial_session_id_invalid_chars() {
        // Special characters should fail
        assert!(validate_session_id("session!@#$%^&*()", 16, 64).is_err());
        assert!(validate_session_id("session<script>", 16, 64).is_err());
        assert!(validate_session_id("session;DROP TABLE", 16, 64).is_err());

        // Null bytes
        assert!(validate_session_id("session\0id12345", 16, 64).is_err());

        // Unicode
        assert!(validate_session_id("session🔑12345678", 16, 64).is_err());
    }

    #[test]
    #[ignore = "perf test - run manually with: cargo test -p octarine test_perf_ -- --ignored"]
    fn test_perf_session_id_validation() {
        // Session ID validation
        let session = "AbCdEf123456GhIjKl789012";
        let iterations = 10000;
        let start = std::time::Instant::now();

        for _ in 0..iterations {
            let _ = validate_session_id(session, 16, 64);
        }

        let duration = start.elapsed();
        let avg_micros = duration.as_micros() / iterations;

        // Session ID validation should be sub-100 microseconds
        assert!(avg_micros < 100, "Average: {} µs", avg_micros);
    }

    proptest! {

        #[test]
        fn prop_no_panic_session_validation(s in "\\PC*") {
                let _ = validate_session_id(&s, 16, 128);
            }

    }
}
