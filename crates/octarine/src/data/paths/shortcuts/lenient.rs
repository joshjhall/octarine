//! Lenient sanitization shortcuts
//!
//! Convenience functions for lenient path cleaning that always return a value.

use super::super::PathBuilder;

// ============================================================
// LENIENT SANITIZATION SHORTCUTS
// ============================================================

/// Clean a path - always returns a safe value
pub fn clean_path(path: &str) -> String {
    PathBuilder::new().clean_path(path)
}

/// Clean a user-provided path - always returns a safe value
pub fn clean_user_path(path: &str) -> String {
    PathBuilder::new().clean_user_path(path)
}

/// Clean a filename - always returns a safe filename
pub fn clean_filename(filename: &str) -> String {
    PathBuilder::new().clean_filename(filename)
}

/// Clean path separators - normalize to Unix style
pub fn clean_separators(path: &str) -> String {
    PathBuilder::new().clean_separators(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_lenient_shortcuts() {
        let cleaned = clean_path("../etc/passwd");
        assert!(!cleaned.contains(".."));

        let safe = clean_filename("bad<>file.txt");
        assert!(!safe.contains('<'));
    }
}
