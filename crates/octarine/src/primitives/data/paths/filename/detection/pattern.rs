//! Pattern matching functions
//!
//! Functions for glob-style pattern matching on filenames.

// Allow arithmetic operations and indexing in this module - they are intentional
// and bounds-checked appropriately for the glob matching algorithm
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::indexing_slicing)]

// ============================================================================
// Pattern Matching
// ============================================================================

/// Check if filename matches a glob-like pattern
///
/// Supports `*` (any characters) and `?` (single character).
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// assert!(detection::is_pattern_found("file.txt", "*.txt"));
/// assert!(detection::is_pattern_found("file.txt", "file.*"));
/// assert!(detection::is_pattern_found("file1.txt", "file?.txt"));
/// assert!(!detection::is_pattern_found("file.pdf", "*.txt"));
/// ```
#[must_use]
pub fn is_pattern_found(filename: &str, pattern: &str) -> bool {
    match_glob(filename, pattern)
}

/// Internal glob matching function
fn match_glob(text: &str, pattern: &str) -> bool {
    let text_chars: Vec<char> = text.chars().collect();
    let pattern_chars: Vec<char> = pattern.chars().collect();
    match_glob_recursive(&text_chars, &pattern_chars, 0, 0)
}

fn match_glob_recursive(text: &[char], pattern: &[char], ti: usize, pi: usize) -> bool {
    if pi >= pattern.len() {
        return ti >= text.len();
    }

    if pattern[pi] == '*' {
        // Try matching zero or more characters
        for skip in 0..=(text.len() - ti) {
            if match_glob_recursive(text, pattern, ti + skip, pi + 1) {
                return true;
            }
        }
        false
    } else if ti >= text.len() {
        false
    } else if pattern[pi] == '?' || pattern[pi] == text[ti] {
        match_glob_recursive(text, pattern, ti + 1, pi + 1)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_pattern_found() {
        // Wildcard
        assert!(is_pattern_found("file.txt", "*.txt"));
        assert!(is_pattern_found("document.txt", "*.txt"));
        assert!(!is_pattern_found("file.pdf", "*.txt"));

        // Prefix
        assert!(is_pattern_found("file.txt", "file.*"));
        assert!(is_pattern_found("file.pdf", "file.*"));
        assert!(!is_pattern_found("document.txt", "file.*"));

        // Single char
        assert!(is_pattern_found("file1.txt", "file?.txt"));
        assert!(is_pattern_found("fileA.txt", "file?.txt"));
        assert!(!is_pattern_found("file12.txt", "file?.txt"));

        // Complex
        assert!(is_pattern_found("report_2024.pdf", "report_????.pdf"));
        assert!(is_pattern_found("data_backup.tar.gz", "data_*.*"));
    }
}
