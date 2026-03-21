//! Identifier Generators
//!
//! Generators for valid and invalid identifiers used in property-based testing.
//! Includes database IDs, UUIDs, slugs, and other common identifier types.

use proptest::prelude::*;

// ============================================================================
// UUID Generators
// ============================================================================

/// Generate valid UUID v4 strings
///
/// Produces UUIDs in the standard format: `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`
/// where y is 8, 9, a, or b.
pub fn arb_uuid_v4() -> impl Strategy<Value = String> {
    // Generate the hex parts
    let hex8 = "[0-9a-f]{8}";
    let hex4 = "[0-9a-f]{4}";
    let hex12 = "[0-9a-f]{12}";
    let version_part = prop_oneof![Just("4"),];
    let variant_part = prop_oneof![Just("8"), Just("9"), Just("a"), Just("b"),];

    (
        hex8,
        hex4,
        version_part,
        "[0-9a-f]{3}",
        variant_part,
        "[0-9a-f]{3}",
        hex12,
    )
        .prop_map(|(p1, p2, ver, p3, var, p4, p5)| {
            format!("{}-{}-{}{}-{}{}-{}", p1, p2, ver, p3, var, p4, p5)
        })
}

/// Generate invalid UUID-like strings
pub fn arb_invalid_uuid() -> impl Strategy<Value = String> {
    prop_oneof![
        // Wrong length
        Just("12345678-1234-1234-1234-12345678901".to_string()),
        Just("12345678-1234-1234-1234-1234567890123".to_string()),
        // Missing hyphens
        Just("123456781234123412341234567890123456".to_string()),
        // Wrong characters
        Just("gggggggg-gggg-4ggg-8ggg-gggggggggggg".to_string()),
        // Wrong version
        Just("12345678-1234-0234-8234-123456789012".to_string()),
        // Empty or whitespace
        Just("".to_string()),
        Just("   ".to_string()),
    ]
}

// ============================================================================
// Database ID Generators
// ============================================================================

/// Generate valid database-style integer IDs
pub fn arb_database_id() -> impl Strategy<Value = i64> {
    1..=i64::MAX
}

/// Generate string representations of database IDs
pub fn arb_database_id_string() -> impl Strategy<Value = String> {
    (1..=999999999i64).prop_map(|n| n.to_string())
}

/// Generate invalid database ID strings
pub fn arb_invalid_database_id() -> impl Strategy<Value = String> {
    prop_oneof![
        // Negative (usually invalid)
        Just("-1".to_string()),
        Just("-999".to_string()),
        // Zero (often invalid)
        Just("0".to_string()),
        // Non-numeric
        Just("abc".to_string()),
        Just("12a34".to_string()),
        // Too large
        Just("99999999999999999999999999999".to_string()),
        // Empty
        Just("".to_string()),
        // With injection attempts
        Just("1; DROP TABLE users".to_string()),
        Just("1 OR 1=1".to_string()),
    ]
}

// ============================================================================
// Slug Generators
// ============================================================================

/// Generate valid URL slugs
///
/// Produces slugs like: `my-article-title`, `post-123`, `hello-world`
pub fn arb_slug() -> impl Strategy<Value = String> {
    let word = "[a-z]{3,10}";
    let num = (0..999u32).prop_map(|n| n.to_string());

    prop_oneof![
        // Single word
        word.prop_map(|w| w),
        // Two words
        (word, word).prop_map(|(a, b)| format!("{}-{}", a, b)),
        // Three words
        (word, word, word).prop_map(|(a, b, c)| format!("{}-{}-{}", a, b, c)),
        // Word with number
        (word, num).prop_map(|(w, n)| format!("{}-{}", w, n)),
    ]
}

/// Generate invalid slugs
pub fn arb_invalid_slug() -> impl Strategy<Value = String> {
    prop_oneof![
        // Uppercase
        Just("My-Article".to_string()),
        // Spaces
        Just("my article".to_string()),
        // Special characters
        Just("my_article!".to_string()),
        Just("my@article".to_string()),
        // Leading/trailing hyphens
        Just("-my-article".to_string()),
        Just("my-article-".to_string()),
        // Double hyphens
        Just("my--article".to_string()),
        // Too long (> 100 chars typically)
        Just("a".repeat(150)),
        // Empty
        Just("".to_string()),
    ]
}

// ============================================================================
// Username Generators
// ============================================================================

/// Generate valid usernames
///
/// Produces usernames following common patterns:
/// - 3-30 characters
/// - Alphanumeric with underscores
/// - Cannot start with underscore
pub fn arb_username() -> impl Strategy<Value = String> {
    let start = "[a-zA-Z]";
    let rest = "[a-zA-Z0-9_]{2,29}";

    (start, rest).prop_map(|(s, r)| format!("{}{}", s, r))
}

/// Generate invalid usernames
pub fn arb_invalid_username() -> impl Strategy<Value = String> {
    prop_oneof![
        // Too short
        Just("ab".to_string()),
        Just("a".to_string()),
        // Starts with underscore
        Just("_user".to_string()),
        // Starts with number
        Just("1user".to_string()),
        // Special characters
        Just("user@name".to_string()),
        Just("user name".to_string()),
        Just("user!name".to_string()),
        // Too long
        Just("a".repeat(50)),
        // Reserved words
        Just("admin".to_string()),
        Just("root".to_string()),
        Just("system".to_string()),
        // Empty
        Just("".to_string()),
    ]
}

// ============================================================================
// File/Path Identifier Generators
// ============================================================================

/// Generate valid filenames (without path)
pub fn arb_filename() -> impl Strategy<Value = String> {
    let name = "[a-zA-Z0-9_-]{1,50}";
    let ext = prop_oneof![
        Just("txt"),
        Just("json"),
        Just("xml"),
        Just("csv"),
        Just("log"),
        Just("md"),
        Just("rs"),
        Just("toml"),
    ];

    (name, ext).prop_map(|(n, e)| format!("{}.{}", n, e))
}

/// Generate invalid/dangerous filenames
pub fn arb_invalid_filename() -> impl Strategy<Value = String> {
    prop_oneof![
        // Path traversal
        Just("../secret.txt".to_string()),
        Just("..\\secret.txt".to_string()),
        // Null bytes
        Just("file\0.txt".to_string()),
        // Reserved names (Windows)
        Just("CON".to_string()),
        Just("PRN".to_string()),
        Just("AUX".to_string()),
        Just("NUL".to_string()),
        Just("COM1".to_string()),
        Just("LPT1".to_string()),
        // Control characters
        Just("file\n.txt".to_string()),
        Just("file\r.txt".to_string()),
        // Empty
        Just("".to_string()),
        // Only dots
        Just(".".to_string()),
        Just("..".to_string()),
        // Hidden file (might be invalid in some contexts)
        Just(".hidden".to_string()),
        // Too long
        Just("a".repeat(300) + ".txt"),
    ]
}

// ============================================================================
// Token/API Key Format Generators
// ============================================================================

/// Generate valid JWT-like tokens (structure only, not cryptographically valid)
pub fn arb_jwt_structure() -> impl Strategy<Value = String> {
    // JWT has 3 base64url-encoded parts separated by dots
    let base64_part = "[A-Za-z0-9_-]{20,100}";

    (base64_part, base64_part, base64_part)
        .prop_map(|(header, payload, sig)| format!("{}.{}.{}", header, payload, sig))
}

/// Generate invalid JWT structures
pub fn arb_invalid_jwt() -> impl Strategy<Value = String> {
    prop_oneof![
        // Wrong number of parts
        Just("header.payload".to_string()),
        Just("header.payload.sig.extra".to_string()),
        Just("onlyonepart".to_string()),
        // Empty parts
        Just("..".to_string()),
        Just("header..sig".to_string()),
        // Invalid characters
        Just("head er.payload.sig".to_string()),
        Just("header!.payload.sig".to_string()),
        // Empty
        Just("".to_string()),
    ]
}

/// Generate session ID patterns
pub fn arb_session_id() -> impl Strategy<Value = String> {
    prop_oneof![
        // Hex format
        "[0-9a-f]{32}".prop_map(|s| s),
        "[0-9a-f]{64}".prop_map(|s| s),
        // Base64 format
        "[A-Za-z0-9+/]{22}==".prop_map(|s| s),
        // UUID format
        arb_uuid_v4(),
    ]
}

// ============================================================================
// Medical/Healthcare Identifiers
// ============================================================================

/// Generate MRN (Medical Record Number) patterns
pub fn arb_mrn() -> impl Strategy<Value = String> {
    prop_oneof![
        // Numeric MRN
        (100000..9999999i32).prop_map(|n| n.to_string()),
        // Alphanumeric MRN
        "[A-Z]{2}[0-9]{6}".prop_map(|s| s),
        // With prefix
        (100000..999999i32).prop_map(|n| format!("MRN{}", n)),
        (100000..999999i32).prop_map(|n| format!("PAT-{}", n)),
    ]
}

/// Generate NPI (National Provider Identifier) patterns
///
/// NPIs are 10-digit numbers with a specific check digit algorithm.
/// These are test patterns, not real NPIs.
pub fn arb_npi() -> impl Strategy<Value = String> {
    // Generate 10-digit numbers starting with 1 (valid NPI prefix)
    (1000000000i64..1999999999i64).prop_map(|n| n.to_string())
}

/// Generate DEA number patterns
///
/// DEA numbers follow a specific format: 2 letters + 7 digits.
/// These are test patterns, not real DEA numbers.
pub fn arb_dea_number() -> impl Strategy<Value = String> {
    let prefix = prop_oneof![
        Just("A"),
        Just("B"),
        Just("C"),
        Just("D"),
        Just("E"),
        Just("F"),
        Just("G"),
        Just("M"),
    ];
    let letter = "[A-Z]";
    let digits = (1000000..9999999i32).prop_map(|n| n.to_string());

    (prefix, letter, digits).prop_map(|(p, l, d)| format!("{}{}{}", p, l, d))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    #[test]
    fn test_uuid_format() {
        let mut runner = TestRunner::default();
        let strategy = arb_uuid_v4();

        for _ in 0..10 {
            let value = strategy
                .new_tree(&mut runner)
                .expect("Failed to create value tree")
                .current();
            // Should match UUID v4 format
            assert_eq!(value.len(), 36, "UUID should be 36 chars: {}", value);
            assert!(
                value.chars().nth(14) == Some('4'),
                "Version should be 4: {}",
                value
            );
            let variant = value
                .chars()
                .nth(19)
                .expect("UUID should have char at position 19");
            assert!(
                matches!(variant, '8' | '9' | 'a' | 'b'),
                "Variant should be 8/9/a/b: {}",
                value
            );
        }
    }

    #[test]
    fn test_slug_format() {
        let mut runner = TestRunner::default();
        let strategy = arb_slug();

        for _ in 0..10 {
            let value = strategy
                .new_tree(&mut runner)
                .expect("Failed to create value tree")
                .current();
            assert!(
                value
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "Slug should be lowercase alphanumeric with hyphens: {}",
                value
            );
        }
    }

    #[test]
    fn test_username_format() {
        let mut runner = TestRunner::default();
        let strategy = arb_username();

        for _ in 0..10 {
            let value = strategy
                .new_tree(&mut runner)
                .expect("Failed to create value tree")
                .current();
            assert!(
                value.len() >= 3,
                "Username should be at least 3 chars: {}",
                value
            );
            assert!(
                value
                    .chars()
                    .next()
                    .expect("Username should have first char")
                    .is_alphabetic(),
                "Username should start with letter: {}",
                value
            );
        }
    }

    #[test]
    fn test_jwt_structure() {
        let mut runner = TestRunner::default();
        let strategy = arb_jwt_structure();

        for _ in 0..10 {
            let value = strategy
                .new_tree(&mut runner)
                .expect("Failed to create value tree")
                .current();
            let parts: Vec<&str> = value.split('.').collect();
            assert_eq!(parts.len(), 3, "JWT should have 3 parts: {}", value);
        }
    }

    #[test]
    fn test_mrn_format() {
        let mut runner = TestRunner::default();
        let strategy = arb_mrn();

        for _ in 0..10 {
            let value = strategy
                .new_tree(&mut runner)
                .expect("Failed to create value tree")
                .current();
            assert!(!value.is_empty(), "MRN should not be empty");
        }
    }
}
