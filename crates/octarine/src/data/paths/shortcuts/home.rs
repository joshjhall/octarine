//! Home directory shortcuts
//!
//! Convenience functions for home directory operations.

use crate::observe::Problem;

use super::super::PathBuilder;

// ============================================================
// HOME DIRECTORY SHORTCUTS
// ============================================================

/// Check if a path contains a home directory reference (~)
pub fn is_home_reference_present(path: &str) -> bool {
    PathBuilder::new().is_home_reference_present(path)
}

/// Expand ~ to the user's home directory
pub fn expand_home(path: &str) -> Result<String, Problem> {
    PathBuilder::new().expand_home(path)
}

/// Collapse the home directory to ~
pub fn collapse_home(path: &str) -> String {
    PathBuilder::new().collapse_home(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_home_shortcuts() {
        assert!(is_home_reference_present("~/Documents"));
        assert!(!is_home_reference_present("/absolute/path"));
    }
}
