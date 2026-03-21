//! UUID detection functions
//!
//! Detection for Universally Unique Identifiers (UUID) versions 1-5.

use super::super::super::common::patterns;
use super::super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};

use super::common::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

// ============================================================================
// Types
// ============================================================================

/// UUID version enumeration
///
/// Represents the UUID version as defined in RFC 4122.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UuidVersion {
    /// Version 1: Time-based UUID
    V1,
    /// Version 2: DCE Security UUID
    V2,
    /// Version 3: Name-based UUID (MD5 hash)
    V3,
    /// Version 4: Random UUID
    V4,
    /// Version 5: Name-based UUID (SHA-1 hash)
    V5,
    /// Unknown or invalid version
    Unknown,
}

impl std::fmt::Display for UuidVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1 => write!(f, "UUID v1 (time-based)"),
            Self::V2 => write!(f, "UUID v2 (DCE security)"),
            Self::V3 => write!(f, "UUID v3 (MD5 name-based)"),
            Self::V4 => write!(f, "UUID v4 (random)"),
            Self::V5 => write!(f, "UUID v5 (SHA-1 name-based)"),
            Self::Unknown => write!(f, "UUID (unknown version)"),
        }
    }
}

// ============================================================================
// Single-Value Detection
// ============================================================================

/// Check if value is a UUID (any version)
#[must_use]
pub fn is_uuid(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::network::UUID_V4.is_match(trimmed)
        || patterns::network::UUID_V5.is_match(trimmed)
        || patterns::network::UUID_ANY.is_match(trimmed)
}

/// Check if value is a UUID v4 (random)
#[must_use]
pub fn is_uuid_v4(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::network::UUID_V4.is_match(trimmed)
}

/// Check if value is a UUID v5 (namespace-based)
#[must_use]
pub fn is_uuid_v5(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::network::UUID_V5.is_match(trimmed)
}

/// Detect UUID version from the string
///
/// Extracts the version nibble from a UUID string and returns the corresponding version.
/// The version is stored in the 13th hex digit (position 14 in the string, accounting for hyphens).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::detection::{detect_uuid_version, UuidVersion};
///
/// assert_eq!(detect_uuid_version("550e8400-e29b-41d4-a716-446655440000"), Some(UuidVersion::V4));
/// assert_eq!(detect_uuid_version("550e8400-e29b-51d4-a716-446655440000"), Some(UuidVersion::V5));
/// assert_eq!(detect_uuid_version("not-a-uuid"), None);
/// ```
#[must_use]
pub fn detect_uuid_version(uuid: &str) -> Option<UuidVersion> {
    // UUID format: xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx
    // M = version (position 14)
    // N = variant (position 19)

    // Basic validation first
    if !patterns::network::UUID_ANY.is_match(uuid) {
        return None;
    }

    // Extract version character at position 14
    let version_char = uuid.chars().nth(14)?;

    match version_char {
        '1' => Some(UuidVersion::V1),
        '2' => Some(UuidVersion::V2),
        '3' => Some(UuidVersion::V3),
        '4' => Some(UuidVersion::V4),
        '5' => Some(UuidVersion::V5),
        _ => Some(UuidVersion::Unknown),
    }
}

// ============================================================================
// Text Scanning
// ============================================================================

/// Find all UUIDs in text
#[must_use]
pub fn find_uuids_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();
    for pattern in patterns::network::uuids() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::Uuid,
                DetectionConfidence::High,
            ));
        }
    }
    deduplicate_matches(matches)
}

// ============================================================================
// Test Data Detection
// ============================================================================

/// Check if UUID is a known test/special UUID
///
/// Detects:
/// - Nil UUID (00000000-0000-0000-0000-000000000000)
/// - Max UUID (ffffffff-ffff-ffff-ffff-ffffffffffff)
/// - Sequential test UUIDs (12345678-1234-1234-1234-123456789abc)
/// - Common test patterns
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::detection::is_test_uuid;
///
/// assert!(is_test_uuid("00000000-0000-0000-0000-000000000000")); // Nil
/// assert!(is_test_uuid("ffffffff-ffff-ffff-ffff-ffffffffffff")); // Max
/// assert!(!is_test_uuid("550e8400-e29b-41d4-a716-446655440000")); // Real UUID
/// ```
#[must_use]
pub fn is_test_uuid(uuid: &str) -> bool {
    let lower = uuid.to_lowercase().replace('-', "");

    // Nil UUID
    if lower == "00000000000000000000000000000000" {
        return true;
    }

    // Max UUID
    if lower == "ffffffffffffffffffffffffffffffff" {
        return true;
    }

    // Sequential test patterns
    let test_patterns = [
        "12345678123412341234123456789abc",
        "00000000000000000000000000000001",
        "11111111111111111111111111111111",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "deadbeefdeadbeefdeadbeefdeadbeef",
        "cafebabecafebabecafebabecafebabe",
        "0123456789abcdef0123456789abcdef",
    ];

    for pattern in &test_patterns {
        if lower == *pattern {
            return true;
        }
    }

    // Check for repeating patterns (same char repeated)
    if !lower.is_empty() {
        let first_char = lower.chars().next().unwrap_or('x');
        if lower.chars().all(|c| c == first_char) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn test_is_uuid() {
        assert!(is_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_uuid("550E8400-E29B-41D4-A716-446655440000")); // uppercase
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("550e8400-e29b-41d4-a716")); // incomplete
    }

    #[test]
    fn test_is_uuid_v4() {
        assert!(is_uuid_v4("550e8400-e29b-41d4-a716-446655440000")); // v4
        assert!(!is_uuid_v4("550e8400-e29b-51d4-a716-446655440000")); // v5
    }

    #[test]
    fn test_is_uuid_v5() {
        assert!(is_uuid_v5("550e8400-e29b-51d4-a716-446655440000")); // v5
        assert!(!is_uuid_v5("550e8400-e29b-41d4-a716-446655440000")); // v4
    }

    #[test]
    fn test_detect_uuid_version() {
        assert_eq!(
            detect_uuid_version("550e8400-e29b-11d4-a716-446655440000"),
            Some(UuidVersion::V1)
        );
        assert_eq!(
            detect_uuid_version("550e8400-e29b-41d4-a716-446655440000"),
            Some(UuidVersion::V4)
        );
        assert_eq!(
            detect_uuid_version("550e8400-e29b-51d4-a716-446655440000"),
            Some(UuidVersion::V5)
        );
        assert_eq!(detect_uuid_version("not-a-uuid"), None);
    }

    #[test]
    fn test_find_uuids_in_text() {
        let text = "UUID 550e8400-e29b-41d4-a716-446655440000 found";
        let matches = find_uuids_in_text(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].matched_text,
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn test_is_test_uuid() {
        // Nil UUID
        assert!(is_test_uuid("00000000-0000-0000-0000-000000000000"));
        // Max UUID
        assert!(is_test_uuid("ffffffff-ffff-ffff-ffff-ffffffffffff"));
        // Sequential
        assert!(is_test_uuid("12345678-1234-1234-1234-123456789abc"));
        // Common patterns
        assert!(is_test_uuid("deadbeef-dead-beef-dead-beefdeadbeef"));
        // Real UUID - not test
        assert!(!is_test_uuid("550e8400-e29b-41d4-a716-446655440000"));
    }
}
