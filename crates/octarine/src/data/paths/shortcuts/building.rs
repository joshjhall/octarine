//! Path building shortcuts
//!
//! Convenience functions for constructing paths.

use crate::observe::Problem;

use super::super::PathBuilder;

// ============================================================
// PATH BUILDING SHORTCUTS
// ============================================================

/// Build a path from base and components with validation
pub fn build_path(base: &str, components: &[&str]) -> Result<String, Problem> {
    PathBuilder::new().build_path(base, components)
}

/// Build an absolute path from base and components
pub fn build_absolute_path(base: &str, components: &[&str]) -> Result<String, Problem> {
    PathBuilder::new().build_absolute_path(base, components)
}

/// Build a file path from directory and filename
pub fn build_file_path(directory: &str, filename: &str) -> Result<String, Problem> {
    PathBuilder::new().build_file_path(directory, filename)
}

/// Build a temporary file path
pub fn build_temp_path(filename: &str) -> String {
    PathBuilder::new().build_temp_path(filename)
}

/// Build a configuration file path
pub fn build_config_path(directory: &str, environment: Option<&str>) -> String {
    PathBuilder::new().build_config_path(directory, environment)
}

/// Join multiple path components safely
pub fn join_components(components: &[&str]) -> Result<String, Problem> {
    PathBuilder::new().join_components(components)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_building_shortcuts() {
        let path = build_file_path("/app/uploads", "doc.pdf").expect("valid path");
        assert_eq!(path, "/app/uploads/doc.pdf");

        let path = build_path("/base", &["sub", "file.txt"]).expect("valid path");
        assert!(path.contains("sub"));
    }
}
