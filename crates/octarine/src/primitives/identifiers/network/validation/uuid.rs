//! UUID validation functions
//!
//! Pure validation functions for UUID identifiers.
//!
//! # Usage
//!
//! For bool checks, use detection layer's `is_uuid_v4()` etc., or call
//! `validate_uuid_v4().is_ok()` for validation-level checks.

use super::super::detection::{UuidVersion, detect_uuid_version, is_uuid_v4, is_uuid_v5};
use crate::primitives::Problem;

// ============================================================================
// UUID Validation
// ============================================================================

/// Validate UUID v4 format
///
/// Returns the UUID version on success.
///
/// # Examples
///
/// ```ignore
/// // Result-based validation
/// let version = validate_uuid_v4("550e8400-e29b-41d4-a716-446655440000")?;
/// assert_eq!(version, UuidVersion::V4);
///
/// // Bool check using .is_ok()
/// if validate_uuid_v4("550e8400-e29b-41d4-a716-446655440000").is_ok() {
///     println!("Valid UUID v4!");
/// }
/// ```
pub fn validate_uuid_v4(uuid: &str) -> Result<UuidVersion, Problem> {
    if !is_uuid_v4(uuid) {
        return Err(Problem::Validation("Invalid UUID v4 format".into()));
    }
    Ok(UuidVersion::V4)
}

/// Validate UUID v5 format
///
/// Returns the UUID version on success.
///
/// # Examples
///
/// ```ignore
/// // Result-based validation
/// let version = validate_uuid_v5("550e8400-e29b-51d4-a716-446655440000")?;
/// assert_eq!(version, UuidVersion::V5);
///
/// // Bool check using .is_ok()
/// if validate_uuid_v5("550e8400-e29b-51d4-a716-446655440000").is_ok() {
///     println!("Valid UUID v5!");
/// }
/// ```
pub fn validate_uuid_v5(uuid: &str) -> Result<UuidVersion, Problem> {
    if !is_uuid_v5(uuid) {
        return Err(Problem::Validation("Invalid UUID v5 format".into()));
    }
    Ok(UuidVersion::V5)
}

/// Validate UUID format (any version)
///
/// Detects and returns the actual UUID version.
///
/// # Examples
///
/// ```ignore
/// // Result-based validation with version detection
/// let version = validate_uuid("550e8400-e29b-41d4-a716-446655440000")?;
/// assert_eq!(version, UuidVersion::V4);
///
/// // Bool check using .is_ok()
/// if validate_uuid(user_input).is_ok() {
///     println!("Valid UUID!");
/// }
/// ```
pub fn validate_uuid(uuid: &str) -> Result<UuidVersion, Problem> {
    let version = detect_uuid_version(uuid)
        .ok_or_else(|| Problem::Validation("Invalid UUID format".into()))?;
    Ok(version)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_validate_uuid_v4() {
        // Valid v4 UUID
        assert!(validate_uuid_v4("550e8400-e29b-41d4-a716-446655440000").is_ok());

        // Invalid v4 UUID (v5)
        assert!(validate_uuid_v4("550e8400-e29b-51d4-a716-446655440000").is_err());

        // Invalid format
        assert!(validate_uuid_v4("not-a-uuid").is_err());
    }

    #[test]
    fn test_validate_uuid_v5() {
        // Valid v5 UUID
        assert!(validate_uuid_v5("550e8400-e29b-51d4-a716-446655440000").is_ok());

        // Invalid v5 UUID (v4)
        assert!(validate_uuid_v5("550e8400-e29b-41d4-a716-446655440000").is_err());

        // Invalid format
        assert!(validate_uuid_v5("not-a-uuid").is_err());
    }

    #[test]
    fn test_validate_uuid() {
        // Valid v4
        assert!(validate_uuid("550e8400-e29b-41d4-a716-446655440000").is_ok());

        // Valid v5
        assert!(validate_uuid("550e8400-e29b-51d4-a716-446655440000").is_ok());

        // Invalid format
        assert!(validate_uuid("not-a-uuid").is_err());
    }

    // ============================================================================
    // Adversarial and Property-Based Tests
    // ============================================================================

    use proptest::prelude::*;

    #[test]
    fn test_adversarial_uuid_format_confusion() {
        // Valid UUIDs
        assert!(validate_uuid("550e8400-e29b-41d4-a716-446655440000").is_ok());

        // Missing hyphens
        assert!(validate_uuid("550e8400e29b41d4a716446655440000").is_err());

        // Wrong hyphen positions
        assert!(validate_uuid("550e8400e-29b-41d4-a716-446655440000").is_err());

        // Too short
        assert!(validate_uuid("550e8400-e29b-41d4-a716-44665544000").is_err());

        // Too long
        assert!(validate_uuid("550e8400-e29b-41d4-a716-4466554400000").is_err());

        // Invalid characters
        assert!(validate_uuid("550e8400-e29b-41d4-a716-44665544gggg").is_err());
    }

    proptest! {

        #[test]
        fn prop_no_panic_uuid_validation(s in "\\PC*") {
            let _ = validate_uuid(&s);
            let _ = validate_uuid_v4(&s);
            let _ = validate_uuid_v5(&s);
        }

        #[test]
        fn prop_uuid_version_consistency(s in "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}") {
            // If any version-specific validation passes, validate_uuid should pass
            if validate_uuid_v4(&s).is_ok() || validate_uuid_v5(&s).is_ok() {
                assert!(validate_uuid(&s).is_ok(), "Version-specific passed but validate_uuid failed");
            }
        }

        #[test]
        fn prop_uuid_version_enforcement(
            version_digit in "[0-35-9a-f]"  // Any digit except '4'
        ) {
            // Create a UUID with the wrong version (version nibble is at position 14)
            let version_char = version_digit
                .chars()
                .next()
                .expect("Proptest regex guarantees non-empty string");
            let uuid = format!("550e8400-e29b-{}1d4-a716-446655440000", version_char);

            // v4 check should reject UUIDs with version != 4
            assert!(validate_uuid_v4(&uuid).is_err(), "Non-v4 UUID with version '{}' accepted as v4", version_char);
        }
    }
}
