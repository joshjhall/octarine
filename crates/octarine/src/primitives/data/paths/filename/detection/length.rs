//! Length detection functions
//!
//! Functions to detect length-related properties of filenames.

// ============================================================================
// Length Detection
// ============================================================================

/// Check if filename exceeds specified length
#[must_use]
pub fn exceeds_length(filename: &str, max_length: usize) -> bool {
    filename.len() > max_length
}

/// Check if filename is empty
#[must_use]
pub fn is_empty(filename: &str) -> bool {
    filename.is_empty()
}

/// Check if filename is whitespace only
#[must_use]
pub fn is_whitespace_only(filename: &str) -> bool {
    !filename.is_empty() && filename.trim().is_empty()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_length_checks() {
        assert!(exceeds_length("file.txt", 5));
        assert!(!exceeds_length("file.txt", 100));
        assert!(!exceeds_length("file.txt", 8));

        assert!(is_empty(""));
        assert!(!is_empty("file.txt"));

        assert!(is_whitespace_only("   "));
        assert!(is_whitespace_only("\t\n"));
        assert!(!is_whitespace_only(""));
        assert!(!is_whitespace_only("file.txt"));
    }
}
