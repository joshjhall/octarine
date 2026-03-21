//! Path type shortcuts
//!
//! Convenience functions for checking path characteristics.

use crate::primitives::data::paths::CharacteristicBuilder;

// ============================================================
// PATH TYPE SHORTCUTS
// ============================================================

/// Check if path is absolute
pub fn is_absolute_path(path: &str) -> bool {
    CharacteristicBuilder::new().is_absolute(path)
}

/// Check if path is relative
pub fn is_relative_path(path: &str) -> bool {
    CharacteristicBuilder::new().is_relative(path)
}

/// Check if path is portable (works on both Unix and Windows)
pub fn is_portable_path(path: &str) -> bool {
    CharacteristicBuilder::new().is_portable(path)
}

/// Check if path is Unix-style
pub fn is_unix_path(path: &str) -> bool {
    CharacteristicBuilder::new().is_unix_path(path)
}

/// Check if path is Windows-style
pub fn is_windows_path(path: &str) -> bool {
    CharacteristicBuilder::new().is_windows_path(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_path_type_shortcuts() {
        assert!(is_absolute_path("/etc/passwd"));
        assert!(is_relative_path("relative/path"));
        assert!(is_unix_path("/home/user"));
        assert!(is_windows_path("C:\\Windows"));
        assert!(is_portable_path("relative/path"));
    }
}
