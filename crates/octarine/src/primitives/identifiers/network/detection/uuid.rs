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
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_uuid() {
        assert!(is_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_uuid("550E8400-E29B-41D4-A716-446655440000")); // uppercase
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("550e8400-e29b-41d4-a716")); // incomplete
    }

    /// `is_uuid` and `primitives::types::is_uuid_shape` must agree.
    ///
    /// The shape predicate was extracted to `primitives::types` so
    /// `primitives::data::network` can recognize UUID path segments without
    /// depending on this module (issue #753). Nothing in the type system keeps
    /// the two definitions aligned, so this test does.
    ///
    /// The corpus is deliberately **whole-string** only: `is_uuid` matches with
    /// regex word boundaries and therefore accepts a UUID embedded in a longer
    /// value, while `is_uuid_shape` is anchored and does not. That divergence is
    /// intended and is asserted separately below rather than being papered over
    /// here.
    #[test]
    fn test_agrees_with_shared_shape_predicate() {
        use crate::primitives::types::is_uuid_shape;

        let corpus = [
            // Valid, one per version, plus case and variant coverage.
            "550e8400-e29b-11d4-a716-446655440000",
            "550e8400-e29b-21d4-9716-446655440000",
            "550e8400-e29b-31d4-b716-446655440000",
            "550e8400-e29b-41d4-a716-446655440000",
            "550e8400-e29b-51d4-8716-446655440000",
            "550E8400-E29B-41D4-A716-446655440000",
            // Rejected for structure.
            "00000000-0000-0000-0000-000000000000", // nil: version 0, variant 0
            "550e8400-e29b-01d4-a716-446655440000", // version 0
            "550e8400-e29b-61d4-a716-446655440000", // version 6
            "550e8400-e29b-41d4-7716-446655440000", // variant 7
            "550e8400-e29b-41d4-c716-446655440000", // variant c
            // Rejected for shape.
            "550e8400-e29b-41d4-a716-44665544000", // one char short
            "550e8400-e29b-41d4-a716-4466554400000", // one char long
            "550e8400-e29b-41d4-a716-44665544000z", // non-hex
            "550e8400e29b41d4a716446655440000",    // unhyphenated
            "not-a-uuid",
            "",
        ];

        // Assertion messages carry the corpus INDEX, not the value: interpolating
        // an identifier is a cleartext-logging sink even here, where the test
        // exists to confirm the identifier is handled correctly.
        for (index, value) in corpus.iter().enumerate() {
            assert_eq!(
                is_uuid(value),
                is_uuid_shape(value),
                "detection and shared shape predicate disagree on corpus[{index}]"
            );
        }
    }

    /// `is_uuid` and `primitives::types::is_uuid_present` must agree on embedded
    /// UUIDs — that is the whole point of the substring variant.
    ///
    /// `is_uuid_present` is what `primitives::data::network` uses to collapse URL
    /// path segments, so a divergence here would silently change which segments
    /// are masked in metrics labels.
    #[test]
    fn test_substring_predicate_agrees_on_embedded_uuids() {
        use crate::primitives::types::{is_uuid_present, is_uuid_shape};

        let embedded = [
            (
                "sentence",
                "request id.550e8400-e29b-41d4-a716-446655440000 received",
            ),
            (
                "filename",
                "report-550e8400-e29b-41d4-a716-446655440000.pdf",
            ),
            ("dotted prefix", "v1.550e8400-e29b-41d4-a716-446655440000"),
            (
                "path segment",
                "/users/550e8400-e29b-41d4-a716-446655440000/orders",
            ),
        ];
        // Messages name the case, never the value (cleartext-logging sink).
        for (name, value) in embedded {
            assert!(is_uuid(value), "detection should match the {name} case");
            assert!(
                is_uuid_present(value),
                "substring predicate should match the {name} case"
            );
            // The anchored predicate is the one that must NOT match these.
            assert!(
                !is_uuid_shape(value),
                "anchored predicate should reject the {name} case"
            );
        }
    }

    #[test]
    fn test_substring_predicate_requires_word_boundaries() {
        use crate::primitives::types::is_uuid_present;

        // Glued to a word character there is no boundary, so neither the regexes
        // nor the substring predicate match. The non-ASCII cases matter because
        // the regex crate's `\b` is Unicode-aware: a byte-level boundary check
        // would read the accent's continuation byte as a non-word character,
        // find a boundary the regex does not, and diverge here.
        for (name, glued) in [
            ("ASCII hex", "abc550e8400-e29b-41d4-a716-446655440000def"),
            (
                "accented letter before",
                "café550e8400-e29b-41d4-a716-446655440000",
            ),
            (
                "accented letter after",
                "550e8400-e29b-41d4-a716-446655440000café",
            ),
            ("CJK before", "日本550e8400-e29b-41d4-a716-446655440000"),
        ] {
            assert!(!is_uuid(glued), "detection should reject {name} glue");
            assert!(
                !is_uuid_present(glued),
                "substring predicate should reject {name} glue"
            );
        }

        // A non-ASCII NON-word character is still a boundary, and both agree.
        let bounded = "«550e8400-e29b-41d4-a716-446655440000»";
        assert!(is_uuid(bounded));
        assert!(is_uuid_present(bounded));
    }

    /// The regex `\w` class is wider than `char::is_alphanumeric()`.
    ///
    /// Marks, join controls, and connector punctuation are all word characters
    /// to `\b`, so glueing one to a UUID removes the boundary. Pinned against
    /// the real regexes because an alphanumeric-only approximation would call
    /// these positions boundaries and diverge.
    #[test]
    fn test_substring_predicate_matches_full_unicode_word_class() {
        use crate::primitives::types::is_uuid_present;

        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        // Messages name the case, never the value: interpolating an identifier
        // into an assertion is a cleartext-logging sink even in a test whose
        // point is that the identifier is rejected.
        for (glue, name) in [
            ('\u{301}', "combining acute"),
            ('\u{200d}', "zero-width joiner"),
            ('\u{203f}', "undertie"),
        ] {
            for (value, side) in [
                (format!("{glue}{uuid}"), "before"),
                (format!("{uuid}{glue}"), "after"),
            ] {
                assert!(
                    !is_uuid(&value),
                    "detection should reject a {name} {side} the UUID"
                );
                assert!(
                    !is_uuid_present(&value),
                    "substring predicate should reject a {name} {side} the UUID"
                );
            }
        }
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
            matches
                .first()
                .expect("should have at least one match")
                .matched_text,
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
