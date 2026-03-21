// Allow clippy lints that are overly strict for this utility module
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::indexing_slicing)]

//! Encoding attack detection patterns
//!
//! Core detection functions for encoding-based attacks in paths.
//! These are pure functions with NO observe dependencies.
//!
//! ## Coverage
//!
//! - Multiple/double encoding (OWASP: "should be regarded as an attack")
//! - Single URL encoding detection
//! - Overlong UTF-8 (cannot exist in Rust &str, but API provided for completeness)
//!
//! ## Design Principles
//!
//! 1. **Pure Functions**: No logging, no side effects
//! 2. **Detection Only**: Returns bool, no Result types
//! 3. **Reusable**: Used by validation and sanitization layers
//!
//! ## Security Standards
//!
//! - OWASP: Canonicalization attacks
//! - CWE-175: Improper Handling of Mixed Encoding

// ============================================================================
// Single Encoding Detection
// ============================================================================

/// Check if path contains any URL-encoded characters
///
/// Detects the presence of percent-encoding (`%XX` where XX is hex).
/// This is informational - single encoding may be legitimate.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::encoding;
///
/// assert!(encoding::is_url_encoding_present("file%20name.txt")); // Space
/// assert!(encoding::is_url_encoding_present("path%2Ffile")); // Forward slash
/// assert!(!encoding::is_url_encoding_present("file name.txt")); // No encoding
/// ```
#[must_use]
pub fn is_url_encoding_present(path: &str) -> bool {
    let bytes = path.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' {
            // Check if followed by two hex digits
            if let Some(slice) = bytes.get(i + 1..i + 3)
                && slice.len() == 2
            {
                let c1 = slice[0] as char;
                let c2 = slice[1] as char;
                if c1.is_ascii_hexdigit() && c2.is_ascii_hexdigit() {
                    return true;
                }
            }
        }
        i += 1;
    }

    false
}

// ============================================================================
// Multiple/Double Encoding Detection
// ============================================================================

/// Check if path has multiple/double encoding (strong attack indicator)
///
/// ## OWASP Guidance
///
/// Per OWASP ESAPI documentation: "Data encoded more than once is not something
/// that a normal user would generate and should be regarded as an attack."
///
/// Multiple encoding is when encoded data is encoded again:
/// - `%2526` = `%26` = `&` (double encoding)
/// - `%252e` = `%2e` = `.` (double encoding)
///
/// This function detects `%25` (encoded `%`) followed by hex digits,
/// which indicates multiple encoding layers.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::encoding;
///
/// assert!(encoding::is_multiple_encoding_present("path%252e%252e")); // Double encoded ..
/// assert!(encoding::is_multiple_encoding_present("%2526")); // Double encoded &
/// assert!(!encoding::is_multiple_encoding_present("%2e%2e")); // Single encoded (not multiple)
/// assert!(!encoding::is_multiple_encoding_present("normal/path")); // No encoding
/// ```
#[must_use]
pub fn is_multiple_encoding_present(path: &str) -> bool {
    let bytes = path.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // Check for %25 (encoded %)
        if let Some(slice) = bytes.get(i..i.saturating_add(5))
            && slice.len() >= 5
        {
            // Looking for %25XX where XX is hex
            if slice[0] == b'%' && slice[1] == b'2' && slice[2] == b'5' {
                let c1 = slice[3] as char;
                let c2 = slice[4] as char;
                if c1.is_ascii_hexdigit() && c2.is_ascii_hexdigit() {
                    return true;
                }
            }
        }
        i = i.saturating_add(1);
    }

    false
}

/// Check for triple or more encoding
///
/// Detects `%252525` pattern which indicates triple encoding.
/// This is an extremely strong attack indicator.
///
/// Encoding levels:
/// - `%` = the actual character
/// - `%25` = single encoding of `%`
/// - `%2525` = double encoding of `%`
/// - `%252525` = triple encoding of `%`
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::encoding;
///
/// assert!(encoding::is_triple_encoding_present("%252525")); // Triple encoded %
/// assert!(!encoding::is_triple_encoding_present("%2525")); // Only double encoded %
/// assert!(!encoding::is_triple_encoding_present("%25")); // Only single encoded %
/// ```
#[must_use]
pub fn is_triple_encoding_present(path: &str) -> bool {
    // %252525 = triple encoded %
    // Pattern: %25 (encoded %) + 25 (encoded %) + 25 (another encoded %)
    path.contains("%252525") || path.to_lowercase().contains("%252525")
}

// ============================================================================
// Overlong UTF-8 Detection
// ============================================================================

/// Check for overlong UTF-8 encoding sequences
///
/// **NOTE**: Overlong UTF-8 is INVALID UTF-8 and cannot exist in a Rust `&str`.
/// Rust's type system guarantees that `&str` contains only valid UTF-8.
///
/// This function exists for API completeness but will always return `false`
/// for valid string inputs. Overlong UTF-8 detection must happen at the byte
/// level (before converting to String/str) using specialized byte-scanning.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::encoding;
///
/// // Always false for valid UTF-8 strings
/// assert!(!encoding::is_overlong_utf8_present("normal/path"));
/// assert!(!encoding::is_overlong_utf8_present("validé")); // Valid UTF-8
/// ```
#[must_use]
pub fn is_overlong_utf8_present(_path: &str) -> bool {
    // Overlong UTF-8 is invalid UTF-8 and cannot exist in a &str.
    // This check would need to happen on raw bytes before UTF-8 validation.
    // By the time data reaches this function as &str, invalid UTF-8 has
    // already been rejected or replaced.
    false
}

// ============================================================================
// Combined Detection
// ============================================================================

/// Check if path has any encoding-based attacks
///
/// Currently detects:
/// - Multiple/double encoding
/// - Triple or more encoding
///
/// **Note**: Single encoding is not considered an attack.
/// **Note**: Overlong UTF-8 cannot be detected in `&str` inputs.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::encoding;
///
/// assert!(encoding::is_encoding_attack_present("path%252e%252e")); // Double encoding
/// assert!(!encoding::is_encoding_attack_present("normal/path"));
/// assert!(!encoding::is_encoding_attack_present("%2e%2e")); // Single encoding (not attack)
/// ```
#[must_use]
pub fn is_encoding_attack_present(path: &str) -> bool {
    is_multiple_encoding_present(path) || is_triple_encoding_present(path)
}

// ============================================================================
// URL Decoding Utilities
// ============================================================================

/// Decode a single percent-encoded sequence
///
/// Takes a `%XX` sequence and returns the decoded byte value if valid.
/// Returns `None` if the input is not a valid percent-encoded sequence.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::encoding;
///
/// assert_eq!(encoding::decode_percent_sequence("%20"), Some(0x20)); // Space
/// assert_eq!(encoding::decode_percent_sequence("%2F"), Some(0x2F)); // /
/// assert_eq!(encoding::decode_percent_sequence("abc"), None); // Not encoded
/// ```
#[must_use]
pub fn decode_percent_sequence(s: &str) -> Option<u8> {
    if s.len() < 3 || !s.starts_with('%') {
        return None;
    }

    let hex = &s[1..3];
    u8::from_str_radix(hex, 16).ok()
}

/// Count the number of encoding layers in a path
///
/// Returns the maximum encoding depth found:
/// - 0 = No encoding
/// - 1 = Single encoding (e.g., `%2e`)
/// - 2 = Double encoding (e.g., `%252e`)
/// - 3+ = Triple or more
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::encoding;
///
/// assert_eq!(encoding::count_encoding_layers("normal/path"), 0);
/// assert_eq!(encoding::count_encoding_layers("%2e%2e"), 1);
/// assert_eq!(encoding::count_encoding_layers("%252e"), 2);
/// assert_eq!(encoding::count_encoding_layers("%252525"), 3);
/// ```
#[must_use]
pub fn count_encoding_layers(path: &str) -> usize {
    if is_triple_encoding_present(path) {
        3
    } else if is_multiple_encoding_present(path) {
        2
    } else if is_url_encoding_present(path) {
        1
    } else {
        0
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Single encoding tests
    #[test]
    fn test_is_url_encoding_present_common() {
        assert!(is_url_encoding_present("file%20name.txt")); // Space
        assert!(is_url_encoding_present("path%2Ffile")); // Forward slash
        assert!(is_url_encoding_present("%2e%2e")); // Dots
        assert!(is_url_encoding_present("file%00.txt")); // Null
    }

    #[test]
    fn test_is_url_encoding_present_case() {
        assert!(is_url_encoding_present("%2f")); // Lowercase
        assert!(is_url_encoding_present("%2F")); // Uppercase
        assert!(is_url_encoding_present("%2E")); // Uppercase dot
    }

    #[test]
    fn test_is_url_encoding_present_safe() {
        assert!(!is_url_encoding_present("normal/path"));
        assert!(!is_url_encoding_present("file.txt"));
        assert!(!is_url_encoding_present("100%")); // % but no valid hex
        assert!(!is_url_encoding_present("%G0")); // Invalid hex
        assert!(!is_url_encoding_present("%2")); // Incomplete
    }

    // Multiple encoding tests
    #[test]
    fn test_is_multiple_encoding_present_double() {
        assert!(is_multiple_encoding_present("path%252e%252e")); // %252e = %2e = .
        assert!(is_multiple_encoding_present("%2526")); // %2526 = %26 = &
        assert!(is_multiple_encoding_present("file%252F")); // %252F = %2F = /
        assert!(is_multiple_encoding_present("%255c")); // %255c = %5c = \
    }

    #[test]
    fn test_is_multiple_encoding_present_safe() {
        assert!(!is_multiple_encoding_present("%2e%2e")); // Single encoding
        assert!(!is_multiple_encoding_present("normal/path"));
        assert!(!is_multiple_encoding_present("%20")); // Single space encoding
        assert!(!is_multiple_encoding_present("file.txt"));
    }

    // Triple encoding tests
    #[test]
    fn test_is_triple_encoding_present() {
        // %252525 = triple encoded %
        assert!(is_triple_encoding_present("%252525"));
        assert!(is_triple_encoding_present("path%252525file"));
        // %2525 = double encoded %, NOT triple
        assert!(!is_triple_encoding_present("%2525"));
        assert!(!is_triple_encoding_present("%25")); // Single
        assert!(!is_triple_encoding_present("normal"));
    }

    // Overlong UTF-8 tests
    #[test]
    fn test_is_overlong_utf8_present() {
        // Always false for &str (which is guaranteed valid UTF-8)
        assert!(!is_overlong_utf8_present("normal/path"));
        assert!(!is_overlong_utf8_present("validé"));
        assert!(!is_overlong_utf8_present("\u{1F600}")); // Emoji

        // Even replacement characters are valid UTF-8
        let overlong_attempt = String::from_utf8_lossy(&[0xC0, 0xAF]).to_string();
        assert!(!is_overlong_utf8_present(&overlong_attempt));
    }

    // Combined detection tests
    #[test]
    fn test_is_encoding_attack_present() {
        assert!(is_encoding_attack_present("%252e%252e")); // Double encoding
        assert!(is_encoding_attack_present("%252525")); // Triple encoding
        assert!(!is_encoding_attack_present("normal/path"));
        assert!(!is_encoding_attack_present("%2e%2e")); // Single encoding is OK
    }

    // Decode tests
    #[test]
    fn test_decode_percent_sequence() {
        assert_eq!(decode_percent_sequence("%20"), Some(0x20)); // Space
        assert_eq!(decode_percent_sequence("%2F"), Some(0x2F)); // /
        assert_eq!(decode_percent_sequence("%2f"), Some(0x2F)); // / (lowercase)
        assert_eq!(decode_percent_sequence("%00"), Some(0x00)); // Null
        assert_eq!(decode_percent_sequence("%FF"), Some(0xFF)); // Max byte
    }

    #[test]
    fn test_decode_percent_sequence_invalid() {
        assert_eq!(decode_percent_sequence("abc"), None); // No %
        assert_eq!(decode_percent_sequence("%"), None); // Too short
        assert_eq!(decode_percent_sequence("%2"), None); // Too short
        assert_eq!(decode_percent_sequence("%GG"), None); // Invalid hex
        assert_eq!(decode_percent_sequence(""), None); // Empty
    }

    // Counting tests
    #[test]
    fn test_count_encoding_layers() {
        assert_eq!(count_encoding_layers("normal/path"), 0);
        assert_eq!(count_encoding_layers("%2e%2e"), 1); // Single encoded .
        assert_eq!(count_encoding_layers("%252e"), 2); // Double encoded .
        // Triple encoding requires %252525 pattern (triple-encoded %)
        assert_eq!(count_encoding_layers("%252525"), 3); // Triple encoded %
        // Note: %25252e doesn't match triple pattern, it's just double encoded
        assert_eq!(count_encoding_layers("%25252e"), 2);
    }

    // Edge cases
    #[test]
    fn test_empty_string() {
        assert!(!is_url_encoding_present(""));
        assert!(!is_multiple_encoding_present(""));
        assert!(!is_triple_encoding_present(""));
        assert!(!is_encoding_attack_present(""));
        assert_eq!(count_encoding_layers(""), 0);
    }

    #[test]
    fn test_partial_encoding() {
        // Incomplete percent sequences
        assert!(!is_url_encoding_present("%")); // Just %
        assert!(!is_url_encoding_present("%2")); // One hex digit
        assert!(!is_url_encoding_present("%%")); // Double %
        assert!(!is_url_encoding_present("100%")); // % at end
    }

    #[test]
    fn test_mixed_encoding() {
        // Path with both safe and encoded segments
        assert!(is_url_encoding_present("safe/path/%2e%2e/file"));
        assert_eq!(count_encoding_layers("safe/path/%2e%2e/file"), 1);
    }
}
