//! Unicode Security Primitives
//!
//! Pure functions for Unicode security operations including normalization,
//! homograph/mixed-script detection, and confusable character handling.
//!
//! ## Architecture
//!
//! This is **Layer 1 (primitives)** - `pub(crate)` only:
//! - Pure utilities using unicode-* crates directly
//! - No observe dependencies
//! - Used by Layer 2 (observe) for internal log normalization
//! - Wrapped by Layer 3 (data/text) for public API
//!
//! ## Security Background
//!
//! Unicode-based attacks exploit visual similarity:
//! - **Homograph attacks**: Cyrillic 'а' (U+0430) looks like Latin 'a' (U+0061)
//! - **Mixed script spoofing**: `аpple.com` looks like `apple.com`
//! - **Normalization confusion**: Different byte sequences render identically
//! - **Invisible manipulation**: Format characters, zero-width chars
//!
//! ## Compliance Coverage
//!
//! | Check | Standard | CWE | Notes |
//! |-------|----------|-----|-------|
//! | Homograph | UTS #39 | CWE-1007 | Insufficient visual distinction |
//! | Mixed script | UTS #39 | CWE-1007 | Script mixing detection |
//! | Normalization | UAX #15 | CWE-289 | Authentication bypass via normalization |
//!
//! ## References
//!
//! - [Unicode Technical Standard #39](https://unicode.org/reports/tr39/) - Security Mechanisms
//! - [Unicode Standard Annex #15](https://unicode.org/reports/tr15/) - Normalization Forms

#![allow(dead_code)]

use unicode_normalization::UnicodeNormalization;
use unicode_security::GeneralSecurityProfile;
use unicode_security::mixed_script::MixedScript;

// ============================================================================
// Types
// ============================================================================

/// Result of Unicode security analysis
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnicodeSecurityResult {
    /// Whether any Unicode security threats were detected
    pub has_threats: bool,
    /// Whether mixed scripts were detected (potential homograph attack)
    pub is_mixed_script: bool,
    /// Whether the text contains confusable characters
    pub has_confusables: bool,
    /// Whether format characters are present
    pub has_format_chars: bool,
    /// Whether private use area characters are present
    pub has_private_use: bool,
    /// The restriction level the identifier conforms to (if applicable)
    pub restriction_level: Option<RestrictionLevel>,
    /// Individual threat details
    pub threats: Vec<UnicodeThreat>,
}

/// A specific Unicode security threat
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnicodeThreat {
    /// Position in the string (byte offset)
    pub position: usize,
    /// The problematic character
    pub character: char,
    /// Type of threat
    pub threat_type: UnicodeThreatType,
    /// Human-readable description
    pub description: String,
}

/// Types of Unicode security threats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnicodeThreatType {
    /// Mixed scripts in the same text (e.g., Cyrillic + Latin)
    MixedScript,
    /// Character that looks like another from a different script
    Confusable,
    /// Format control character (invisible)
    FormatChar,
    /// Private use area character (undefined semantics)
    PrivateUse,
    /// Bidirectional override character
    BidiOverride,
    /// Zero-width character
    ZeroWidth,
}

impl UnicodeThreatType {
    /// Get the CWE identifier for this threat type
    #[must_use]
    pub const fn cwe(&self) -> &'static str {
        match self {
            Self::MixedScript | Self::Confusable => "CWE-1007",
            Self::FormatChar | Self::BidiOverride | Self::ZeroWidth => "CWE-116",
            Self::PrivateUse => "CWE-20",
        }
    }

    /// Get a human-readable description
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::MixedScript => "Mixed scripts detected (potential homograph attack)",
            Self::Confusable => "Confusable character detected",
            Self::FormatChar => "Format control character detected",
            Self::PrivateUse => "Private use area character detected",
            Self::BidiOverride => "Bidirectional override character detected",
            Self::ZeroWidth => "Zero-width character detected",
        }
    }
}

/// Unicode restriction levels from UTS #39
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RestrictionLevel {
    /// ASCII only
    Ascii,
    /// Single script (recommended for identifiers)
    SingleScript,
    /// Highly restrictive (limited script combinations)
    HighlyRestrictive,
    /// Moderately restrictive
    ModeratelyRestrictive,
    /// Minimally restrictive
    MinimallyRestrictive,
    /// Unrestricted
    Unrestricted,
}

// ============================================================================
// Normalization Functions
// ============================================================================

/// Normalize text to NFC (Canonical Composition)
///
/// NFC is the recommended default normalization form. It composes characters
/// where possible (e.g., combining accents with base characters).
///
/// # Example
///
/// ```ignore
/// let normalized = normalize_nfc("café");
/// ```
#[must_use]
pub fn normalize_nfc(input: &str) -> String {
    input.nfc().collect()
}

/// Normalize text to NFKC (Compatibility Composition)
///
/// NFKC is more aggressive than NFC. It also converts compatibility characters
/// to their canonical equivalents (e.g., ligatures, width variants).
///
/// # Example
///
/// ```ignore
/// let normalized = normalize_nfkc("ﬁle"); // Returns "file"
/// ```
#[must_use]
pub fn normalize_nfkc(input: &str) -> String {
    input.nfkc().collect()
}

/// Normalize text to NFD (Canonical Decomposition)
///
/// NFD decomposes characters into base + combining characters.
#[must_use]
pub fn normalize_nfd(input: &str) -> String {
    input.nfd().collect()
}

/// Normalize text to NFKD (Compatibility Decomposition)
///
/// NFKD decomposes characters and also handles compatibility mappings.
#[must_use]
pub fn normalize_nfkd(input: &str) -> String {
    input.nfkd().collect()
}

/// Check if text is already in NFC form
#[must_use]
pub fn is_nfc(input: &str) -> bool {
    unicode_normalization::is_nfc(input)
}

/// Check if text is already in NFKC form
#[must_use]
pub fn is_nfkc(input: &str) -> bool {
    unicode_normalization::is_nfkc(input)
}

/// Check if text is already in NFD form
#[must_use]
pub fn is_nfd(input: &str) -> bool {
    unicode_normalization::is_nfd(input)
}

/// Check if text is already in NFKD form
#[must_use]
pub fn is_nfkd(input: &str) -> bool {
    unicode_normalization::is_nfkd(input)
}

// ============================================================================
// Mixed Script Detection (Homograph Prevention)
// ============================================================================

/// Check if text contains mixed scripts (potential homograph attack)
///
/// Returns true if the text contains characters from multiple scripts
/// that could be used for spoofing (e.g., Cyrillic mixed with Latin).
///
/// # Example
///
/// ```ignore
/// assert!(is_mixed_script_present("аpple.com"));  // Cyrillic а + Latin
/// assert!(!is_mixed_script_present("apple.com")); // Pure Latin
/// assert!(!is_mixed_script_present("Москва"));    // Pure Cyrillic
/// ```
#[must_use]
pub fn is_mixed_script_present(input: &str) -> bool {
    // Use unicode-security's mixed script detection
    !input.is_single_script()
}

/// Check if text uses only a single script (safe for identifiers)
#[must_use]
pub fn is_single_script(input: &str) -> bool {
    input.is_single_script()
}

// ============================================================================
// Confusable Detection
// ============================================================================

/// Get the "skeleton" of a string for confusable comparison
///
/// The skeleton algorithm from UTS #39 maps confusable characters to a
/// canonical form. Two strings with the same skeleton are visually confusable.
///
/// # Example
///
/// ```ignore
/// // Cyrillic 'а' and Latin 'a' have the same skeleton
/// assert_eq!(skeleton("apple"), skeleton("аpple"));
/// ```
#[must_use]
pub fn skeleton(input: &str) -> String {
    unicode_security::confusable_detection::skeleton(input).collect()
}

/// Check if two strings are confusable (visually similar)
///
/// Returns true if the strings have the same skeleton.
#[must_use]
pub fn is_confusable_with(a: &str, b: &str) -> bool {
    skeleton(a) == skeleton(b)
}

/// Check if text contains any confusable characters
///
/// Returns true if normalizing to skeleton would change the text,
/// indicating presence of characters that could be confused with others.
#[must_use]
pub fn is_confusable_chars_present(input: &str) -> bool {
    let skel = skeleton(input);
    // If skeleton differs from NFKC, confusables are present
    let normalized = normalize_nfkc(input);
    skel != normalized
}

// ============================================================================
// General Security Profile
// ============================================================================

/// Check if a string conforms to the General Security Profile for identifiers
///
/// The General Security Profile (from UTS #39) defines which characters
/// are safe for use in identifiers across different contexts.
#[must_use]
pub fn is_identifier_safe(input: &str) -> bool {
    input.chars().all(|c| c.identifier_allowed())
}

/// Check if a character is allowed in identifiers per UTS #39
#[must_use]
pub fn is_char_identifier_allowed(c: char) -> bool {
    c.identifier_allowed()
}

// ============================================================================
// Format and Special Character Detection
// ============================================================================

/// Check if text contains format control characters
///
/// Format characters are invisible and can be used to manipulate display.
/// Includes soft hyphens, zero-width joiners, etc.
#[must_use]
pub fn is_format_chars_present(input: &str) -> bool {
    input.chars().any(is_format_char)
}

/// Check if a character is a format control character
#[must_use]
pub fn is_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'          // Soft hyphen
        | '\u{200B}'        // Zero-width space
        | '\u{200C}'        // Zero-width non-joiner
        | '\u{200D}'        // Zero-width joiner
        | '\u{200E}'        // Left-to-right mark
        | '\u{200F}'        // Right-to-left mark
        | '\u{2028}'        // Line separator
        | '\u{2029}'        // Paragraph separator
        | '\u{202A}'..='\u{202E}' // Bidi embedding controls
        | '\u{2060}'..='\u{2064}' // Invisible operators
        | '\u{2066}'..='\u{2069}' // Bidi isolate controls
        | '\u{FEFF}'        // Byte order mark / zero-width no-break space
        | '\u{FFF9}'..='\u{FFFB}' // Interlinear annotation anchors
    )
}

/// Check if text contains private use area characters
///
/// Private use characters have no defined meaning and could be
/// used to bypass security checks.
#[must_use]
pub fn is_private_use_present(input: &str) -> bool {
    input.chars().any(is_private_use_char)
}

/// Check if a character is in the private use area
#[must_use]
pub fn is_private_use_char(c: char) -> bool {
    matches!(
        c as u32,
        0xE000..=0xF8FF        // BMP Private Use Area
        | 0xF0000..=0xFFFFD   // Supplementary PUA-A
        | 0x100000..=0x10FFFD // Supplementary PUA-B
    )
}

/// Check if text contains zero-width characters
#[must_use]
pub fn is_zero_width_present(input: &str) -> bool {
    input.chars().any(is_zero_width_char)
}

/// Check if a character is zero-width
#[must_use]
pub fn is_zero_width_char(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'  // Zero-width space
        | '\u{200C}' // Zero-width non-joiner
        | '\u{200D}' // Zero-width joiner
        | '\u{FEFF}' // Zero-width no-break space (BOM)
    )
}

/// Check if text contains bidirectional override characters
#[must_use]
pub fn is_bidi_override_present(input: &str) -> bool {
    input.chars().any(is_bidi_override_char)
}

/// Check if a character is a bidirectional override
#[must_use]
pub fn is_bidi_override_char(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'  // Left-to-right embedding
        | '\u{202B}' // Right-to-left embedding
        | '\u{202C}' // Pop directional formatting
        | '\u{202D}' // Left-to-right override
        | '\u{202E}' // Right-to-left override
        | '\u{2066}' // Left-to-right isolate
        | '\u{2067}' // Right-to-left isolate
        | '\u{2068}' // First strong isolate
        | '\u{2069}' // Pop directional isolate
    )
}

// ============================================================================
// Combined Security Analysis
// ============================================================================

/// Perform comprehensive Unicode security analysis
///
/// Checks for all known Unicode security threats and returns detailed results.
#[must_use]
pub fn detect_unicode_threats(input: &str) -> UnicodeSecurityResult {
    // Check individual categories
    let is_mixed_script = is_mixed_script_present(input);
    let has_confusables = is_confusable_chars_present(input);
    let has_format_chars = is_format_chars_present(input);
    let has_private_use = is_private_use_present(input);

    // Collect individual threats with positions
    let threats: Vec<UnicodeThreat> = input
        .char_indices()
        .filter_map(|(idx, c)| {
            if is_format_char(c) {
                Some(UnicodeThreat {
                    position: idx,
                    character: c,
                    threat_type: if is_bidi_override_char(c) {
                        UnicodeThreatType::BidiOverride
                    } else if is_zero_width_char(c) {
                        UnicodeThreatType::ZeroWidth
                    } else {
                        UnicodeThreatType::FormatChar
                    },
                    description: format!("Format character U+{:04X}", c as u32),
                })
            } else if is_private_use_char(c) {
                Some(UnicodeThreat {
                    position: idx,
                    character: c,
                    threat_type: UnicodeThreatType::PrivateUse,
                    description: format!("Private use character U+{:04X}", c as u32),
                })
            } else {
                None
            }
        })
        .collect();

    // Build result with struct initialization
    UnicodeSecurityResult {
        has_threats: is_mixed_script || has_confusables || has_format_chars || has_private_use,
        is_mixed_script,
        has_confusables,
        has_format_chars,
        has_private_use,
        restriction_level: None,
        threats,
    }
}

/// Check if text is secure (no Unicode threats detected)
#[must_use]
pub fn is_unicode_secure(input: &str) -> bool {
    !is_mixed_script_present(input)
        && !is_format_chars_present(input)
        && !is_private_use_present(input)
}

// ============================================================================
// Sanitization
// ============================================================================

/// Sanitize text by removing dangerous Unicode characters
///
/// Removes format characters, private use characters, and normalizes to NFC.
#[must_use]
pub fn sanitize_unicode(input: &str) -> String {
    input
        .chars()
        .filter(|&c| !is_format_char(c) && !is_private_use_char(c))
        .collect::<String>()
        .nfc()
        .collect()
}

/// Strip all zero-width characters from text
#[must_use]
pub fn strip_zero_width(input: &str) -> String {
    input.chars().filter(|&c| !is_zero_width_char(c)).collect()
}

/// Strip all format control characters from text
#[must_use]
pub fn strip_format_chars(input: &str) -> String {
    input.chars().filter(|&c| !is_format_char(c)).collect()
}

/// Strip bidirectional override characters from text
#[must_use]
pub fn strip_bidi_overrides(input: &str) -> String {
    input
        .chars()
        .filter(|&c| !is_bidi_override_char(c))
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ========================================================================
    // Normalization Tests
    // ========================================================================

    #[test]
    fn test_normalize_nfc() {
        // Composed form should stay composed
        let composed = "café";
        assert!(is_nfc(composed) || normalize_nfc(composed) == composed);
    }

    #[test]
    fn test_normalize_nfkc_ligature() {
        // Ligature should be expanded
        let with_ligature = "ﬁle";
        let normalized = normalize_nfkc(with_ligature);
        assert_eq!(normalized, "file");
    }

    #[test]
    fn test_normalize_nfkc_fullwidth() {
        // Fullwidth should be normalized
        let fullwidth = "ＡＢＣＤ";
        let normalized = normalize_nfkc(fullwidth);
        assert_eq!(normalized, "ABCD");
    }

    // ========================================================================
    // Mixed Script Tests
    // ========================================================================

    #[test]
    fn test_mixed_script_cyrillic_latin() {
        // Cyrillic 'а' (U+0430) mixed with Latin
        let mixed = "аpple"; // Cyrillic а + Latin pple
        assert!(is_mixed_script_present(mixed));
    }

    #[test]
    fn test_pure_latin() {
        let pure = "apple";
        assert!(!is_mixed_script_present(pure));
    }

    #[test]
    fn test_pure_cyrillic() {
        let pure = "Москва";
        assert!(!is_mixed_script_present(pure));
    }

    #[test]
    fn test_single_script() {
        assert!(is_single_script("hello"));
        assert!(is_single_script("Москва"));
        assert!(is_single_script("日本語"));
    }

    // ========================================================================
    // Confusable Tests
    // ========================================================================

    #[test]
    fn test_skeleton_confusables() {
        // Cyrillic 'а' and Latin 'a' should have same skeleton
        let latin = "apple";
        let cyrillic = "аpple"; // Cyrillic а

        let skel_latin = skeleton(latin);
        let skel_cyrillic = skeleton(cyrillic);

        assert_eq!(skel_latin, skel_cyrillic);
    }

    #[test]
    fn test_is_confusable_with() {
        assert!(is_confusable_with("apple", "аpple")); // Latin vs Cyrillic а
        assert!(!is_confusable_with("apple", "banana"));
    }

    // ========================================================================
    // Format Character Tests
    // ========================================================================

    #[test]
    fn test_format_chars_present() {
        let with_zwj = "hello\u{200D}world"; // Zero-width joiner
        assert!(is_format_chars_present(with_zwj));

        let clean = "hello world";
        assert!(!is_format_chars_present(clean));
    }

    #[test]
    fn test_zero_width_present() {
        let with_zws = "hello\u{200B}world"; // Zero-width space
        assert!(is_zero_width_present(with_zws));

        let clean = "hello world";
        assert!(!is_zero_width_present(clean));
    }

    #[test]
    fn test_bidi_override_present() {
        let with_rlo = "hello\u{202E}world"; // Right-to-left override
        assert!(is_bidi_override_present(with_rlo));

        let clean = "hello world";
        assert!(!is_bidi_override_present(clean));
    }

    // ========================================================================
    // Private Use Tests
    // ========================================================================

    #[test]
    fn test_private_use_present() {
        let with_pua = "hello\u{E000}world"; // Private use
        assert!(is_private_use_present(with_pua));

        let clean = "hello world";
        assert!(!is_private_use_present(clean));
    }

    // ========================================================================
    // Combined Security Tests
    // ========================================================================

    #[test]
    fn test_detect_threats_clean() {
        let result = detect_unicode_threats("hello world");
        assert!(!result.has_threats);
        assert!(!result.is_mixed_script);
        assert!(!result.has_format_chars);
        assert!(!result.has_private_use);
    }

    #[test]
    fn test_detect_threats_mixed_script() {
        let result = detect_unicode_threats("аpple"); // Cyrillic а
        assert!(result.has_threats);
        assert!(result.is_mixed_script);
    }

    #[test]
    fn test_detect_threats_format_chars() {
        let result = detect_unicode_threats("hello\u{200B}world");
        assert!(result.has_threats);
        assert!(result.has_format_chars);
        assert!(!result.threats.is_empty());
    }

    #[test]
    fn test_is_unicode_secure() {
        assert!(is_unicode_secure("hello world"));
        assert!(is_unicode_secure("apple.com"));
        assert!(!is_unicode_secure("аpple.com")); // Cyrillic а
        assert!(!is_unicode_secure("hello\u{200B}world"));
    }

    // ========================================================================
    // Sanitization Tests
    // ========================================================================

    #[test]
    fn test_sanitize_unicode() {
        let dirty = "hello\u{200B}\u{200D}world"; // Zero-width chars
        let clean = sanitize_unicode(dirty);
        assert_eq!(clean, "helloworld");
    }

    #[test]
    fn test_strip_zero_width() {
        let with_zws = "he\u{200B}llo";
        assert_eq!(strip_zero_width(with_zws), "hello");
    }

    #[test]
    fn test_strip_format_chars() {
        let with_format = "he\u{200D}llo\u{FEFF}";
        assert_eq!(strip_format_chars(with_format), "hello");
    }

    #[test]
    fn test_strip_bidi_overrides() {
        let with_bidi = "he\u{202E}llo";
        assert_eq!(strip_bidi_overrides(with_bidi), "hello");
    }

    // ========================================================================
    // Identifier Safety Tests
    // ========================================================================

    #[test]
    fn test_identifier_safe() {
        assert!(is_identifier_safe("hello_world"));
        assert!(is_identifier_safe("Москва"));
    }

    #[test]
    fn test_char_identifier_allowed() {
        assert!(is_char_identifier_allowed('a'));
        assert!(is_char_identifier_allowed('_'));
        // Format chars are not allowed in identifiers
        assert!(!is_char_identifier_allowed('\u{200B}'));
    }
}
