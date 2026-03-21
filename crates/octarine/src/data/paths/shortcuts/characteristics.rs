//! Additional path characteristic shortcuts
//!
//! Convenience functions for checking path characteristics.

use super::super::CharacteristicBuilder;

// ============================================================
// ADDITIONAL PATH CHARACTERISTIC SHORTCUTS
// ============================================================

/// Check if path or filename is hidden (starts with .)
pub fn is_hidden(path: &str) -> bool {
    CharacteristicBuilder::new().is_hidden(path)
}

/// Check if path contains any hidden component
pub fn is_hidden_component_present(path: &str) -> bool {
    CharacteristicBuilder::new().is_hidden_component_present(path)
}

/// Calculate the depth of a path (number of components)
///
/// # Examples
///
/// ```rust
/// use octarine::data::paths::calculate_depth;
/// assert_eq!(calculate_depth("a/b/c"), 3);
/// assert_eq!(calculate_depth("file.txt"), 1);
/// ```
pub fn calculate_depth(path: &str) -> usize {
    CharacteristicBuilder::new().calculate_path_depth(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_characteristics() {
        assert!(is_hidden(".hidden"));
        assert!(!is_hidden("visible"));
        assert!(is_hidden_component_present("path/.hidden/file"));
        assert_eq!(calculate_depth("a/b/c"), 3);
    }
}
