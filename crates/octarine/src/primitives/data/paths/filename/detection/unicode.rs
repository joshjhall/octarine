//! Unicode detection functions
//!
//! Functions to detect Unicode-related security issues in filenames.

// ============================================================================
// Unicode Detection
// ============================================================================

/// Check if filename contains non-ASCII characters
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// assert!(detection::is_non_ascii_present("文件.txt"));
/// assert!(detection::is_non_ascii_present("café.txt"));
/// assert!(!detection::is_non_ascii_present("file.txt"));
/// ```
#[must_use]
pub fn is_non_ascii_present(filename: &str) -> bool {
    !filename.is_ascii()
}

/// Check if filename contains Unicode homoglyphs
///
/// Homoglyphs are characters that look similar to ASCII but are different,
/// potentially enabling phishing attacks (e.g., Cyrillic 'а' vs Latin 'a').
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// // Cyrillic 'а' (U+0430) looks like Latin 'a'
/// assert!(detection::is_homoglyphs_present("pаypal.txt")); // Contains Cyrillic 'а'
/// assert!(!detection::is_homoglyphs_present("paypal.txt")); // All ASCII
/// ```
#[must_use]
pub fn is_homoglyphs_present(filename: &str) -> bool {
    // Common homoglyph ranges that look like ASCII letters
    filename.chars().any(|c| {
        matches!(c,
            // Cyrillic characters that look like Latin
            '\u{0430}'..='\u{044f}' | // Cyrillic small letters
            '\u{0410}'..='\u{042f}' | // Cyrillic capital letters
            // Greek characters
            '\u{03B1}'..='\u{03C9}' | // Greek small letters
            '\u{0391}'..='\u{03A9}' | // Greek capital letters
            // Full-width characters
            '\u{FF01}'..='\u{FF5E}'   // Full-width ASCII variants
        )
    })
}

/// Check if filename has Unicode bidirectional control characters
///
/// These can be used to make filenames appear different than they are.
#[must_use]
pub fn is_bidi_control_present(filename: &str) -> bool {
    filename.chars().any(|c| {
        matches!(
            c,
            '\u{200E}' | // Left-to-right mark
            '\u{200F}' | // Right-to-left mark
            '\u{202A}' | // Left-to-right embedding
            '\u{202B}' | // Right-to-left embedding
            '\u{202C}' | // Pop directional formatting
            '\u{202D}' | // Left-to-right override
            '\u{202E}' | // Right-to-left override
            '\u{2066}' | // Left-to-right isolate
            '\u{2067}' | // Right-to-left isolate
            '\u{2068}' | // First strong isolate
            '\u{2069}' // Pop directional isolate
        )
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_non_ascii_present() {
        assert!(is_non_ascii_present("文件.txt"));
        assert!(is_non_ascii_present("café.txt"));
        assert!(is_non_ascii_present("naïve.txt"));
        assert!(!is_non_ascii_present("file.txt"));
        assert!(!is_non_ascii_present("file-name_123.txt"));
    }

    #[test]
    fn test_is_homoglyphs_present() {
        // Cyrillic 'а' (U+0430) looks like Latin 'a'
        assert!(is_homoglyphs_present("p\u{0430}ypal.txt"));
        // Greek 'ο' (U+03BF) looks like Latin 'o'
        assert!(is_homoglyphs_present("g\u{03BF}ogle.txt"));
        // Full-width 'a' (U+FF41)
        assert!(is_homoglyphs_present("\u{FF41}pple.txt"));
        // All ASCII
        assert!(!is_homoglyphs_present("paypal.txt"));
        assert!(!is_homoglyphs_present("google.txt"));
    }

    #[test]
    fn test_is_bidi_control_present() {
        // Right-to-left override
        assert!(is_bidi_control_present("file\u{202E}txt.exe"));
        // Left-to-right mark
        assert!(is_bidi_control_present("file\u{200E}.txt"));
        // Normal
        assert!(!is_bidi_control_present("file.txt"));
    }
}
