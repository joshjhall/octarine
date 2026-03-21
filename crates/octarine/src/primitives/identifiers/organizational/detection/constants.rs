// SAFETY: All expect() calls in this module are on capture.get(0), which always exists
// per the regex spec (group 0 is the full match and is guaranteed to exist).
#![allow(clippy::expect_used)]

//! Constants and utility functions for organizational ID detection
//!
//! Provides length limits for ReDoS protection and input validation.

// ============================================================================
// Constants
// ============================================================================

/// Maximum input length for ReDoS protection
///
/// Inputs longer than this are rejected to prevent regex denial of service.
pub const MAX_INPUT_LENGTH: usize = 10_000;

/// Maximum single identifier length
///
/// Individual identifiers (employee IDs, student IDs, etc.) shouldn't exceed this.
pub const MAX_IDENTIFIER_LENGTH: usize = 100;

/// Check if input exceeds safe length for regex processing
///
/// Used for ReDoS protection in text scanning functions.
#[inline]
pub fn exceeds_safe_length(input: &str, max_len: usize) -> bool {
    input.len() > max_len
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_exceeds_safe_length() {
        assert!(!exceeds_safe_length("short", 100));
        assert!(exceeds_safe_length("a".repeat(101).as_str(), 100));
        assert!(!exceeds_safe_length("exact", 5));
    }

    #[test]
    fn test_constants() {
        assert_eq!(MAX_INPUT_LENGTH, 10_000);
        assert_eq!(MAX_IDENTIFIER_LENGTH, 100);
    }
}
