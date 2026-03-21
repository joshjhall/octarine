//! Core path construction functions
//!
//! Safe path construction from validated components.

use crate::observe::Problem;
use crate::primitives::data::paths::PathBuilder as PrimitivePathBuilder;
use crate::primitives::security::paths::SecurityBuilder;
use std::env;

/// Build a path from a base and components with validation
///
/// Each component is validated before being joined to ensure no
/// path traversal or injection attacks.
pub(in crate::data::paths) fn build_path(
    base: &str,
    components: &[&str],
) -> Result<String, Problem> {
    let security = SecurityBuilder::new();
    let path_builder = PrimitivePathBuilder::new();

    // Validate base
    if security.is_threat_present(base) {
        return Err(Problem::security("Base path contains security threats"));
    }

    let mut result = base.to_string();

    for component in components {
        // Validate each component
        if component.is_empty() {
            continue; // Skip empty components
        }

        if component.contains('/') || component.contains('\\') {
            return Err(Problem::validation(
                "Path components cannot contain separators; use multiple components instead",
            ));
        }

        if *component == ".." {
            return Err(Problem::security(
                "Path traversal (..) not allowed in path components",
            ));
        }

        if *component == "." {
            continue; // Skip current directory references
        }

        if security.is_null_bytes_present(component) {
            return Err(Problem::security(
                "Null bytes not allowed in path components",
            ));
        }

        if security.is_command_injection_present(component) {
            return Err(Problem::security(
                "Command injection patterns not allowed in path components",
            ));
        }

        // Join the validated component
        result = path_builder.join(&result, component);
    }

    Ok(result)
}

/// Build an absolute path from base and components
///
/// Ensures the result is an absolute path.
pub(in crate::data::paths) fn build_absolute_path(
    base: &str,
    components: &[&str],
) -> Result<String, Problem> {
    let result = build_path(base, components)?;

    // Ensure it's absolute
    if !result.starts_with('/') && !result.contains(':') {
        return Err(Problem::validation(
            "Base must be an absolute path for build_absolute_path",
        ));
    }

    Ok(result)
}

/// Join multiple path components safely
pub(in crate::data::paths) fn join_path_components(components: &[&str]) -> Result<String, Problem> {
    if components.is_empty() {
        return Err(Problem::validation(
            "Cannot join empty list of path components",
        ));
    }

    // Safe: we checked components is non-empty above
    let Some((base, rest)) = components.split_first() else {
        return Err(Problem::validation(
            "Cannot join empty list of path components",
        ));
    };
    build_path(base, rest)
}

/// Build a file path from directory and filename
pub(in crate::data::paths) fn build_file_path(
    directory: &str,
    filename: &str,
) -> Result<String, Problem> {
    build_path(directory, &[filename])
}

/// Build a temporary file path
///
/// Uses the system temp directory and sanitizes the filename.
pub(in crate::data::paths) fn build_temp_path(filename: &str) -> String {
    let temp_dir = env::temp_dir();
    let temp_str = temp_dir.to_string_lossy();

    // Sanitize the filename to be safe
    let safe_filename = sanitize_filename_for_temp(filename);

    PrimitivePathBuilder::new().join(&temp_str, &safe_filename)
}

/// Build a configuration file path
///
/// Constructs a path in a standard config directory.
pub(in crate::data::paths) fn build_config_path(
    directory: &str,
    environment: Option<&str>,
) -> String {
    let path_builder = PrimitivePathBuilder::new();

    match environment {
        Some(env) => {
            let config_name = format!("config.{}.yaml", env);
            path_builder.join(directory, &config_name)
        }
        None => path_builder.join(directory, "config.yaml"),
    }
}

/// Sanitize a filename for use in temp paths
fn sanitize_filename_for_temp(filename: &str) -> String {
    // Remove dangerous characters
    let mut result = String::with_capacity(filename.len());

    for c in filename.chars() {
        match c {
            // Allow alphanumeric, dot, dash, underscore
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => result.push(c),
            // Replace others with underscore
            _ => result.push('_'),
        }
    }

    // Ensure it's not empty
    if result.is_empty() {
        return "temp_file".to_string();
    }

    // Ensure it doesn't start with a dot (hidden file)
    if result.starts_with('.') {
        result = format!("_{}", &result[1..]);
    }

    // Limit length
    if result.len() > 255 {
        result.truncate(255);
    }

    result
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_build_path_valid() {
        let result = build_path("/app", &["data", "file.txt"]).expect("valid path");
        assert_eq!(result, "/app/data/file.txt");
    }

    #[test]
    fn test_build_path_empty_components() {
        let result =
            build_path("/app", &["", "data", "", "file.txt"]).expect("filters empty components");
        assert_eq!(result, "/app/data/file.txt");
    }

    #[test]
    fn test_build_path_rejects_traversal() {
        assert!(build_path("/app", &["..", "etc", "passwd"]).is_err());
    }

    #[test]
    fn test_build_path_rejects_separators_in_components() {
        assert!(build_path("/app", &["data/subdir"]).is_err());
        assert!(build_path("/app", &["data\\subdir"]).is_err());
    }

    #[test]
    fn test_build_path_rejects_command_injection() {
        assert!(build_path("/app", &["$(whoami)"]).is_err());
        assert!(build_path("/app", &["`id`"]).is_err());
    }

    #[test]
    fn test_build_absolute_path() {
        let result = build_absolute_path("/app", &["data"]).expect("valid absolute path");
        assert_eq!(result, "/app/data");

        // Relative base should fail
        assert!(build_absolute_path("relative", &["data"]).is_err());
    }

    #[test]
    fn test_join_path_components() {
        let result =
            join_path_components(&["/app", "data", "file.txt"]).expect("valid joined path");
        assert_eq!(result, "/app/data/file.txt");

        assert!(join_path_components(&[]).is_err());
    }

    #[test]
    fn test_build_temp_path() {
        let result = build_temp_path("myfile.txt");
        assert!(result.contains("myfile.txt"));
    }

    #[test]
    fn test_build_temp_path_sanitizes() {
        let result = build_temp_path("bad<>file.txt");
        assert!(!result.contains('<'));
        assert!(!result.contains('>'));
    }

    #[test]
    fn test_build_config_path() {
        let result = build_config_path("/etc/myapp", None);
        assert_eq!(result, "/etc/myapp/config.yaml");

        let result = build_config_path("/etc/myapp", Some("production"));
        assert_eq!(result, "/etc/myapp/config.production.yaml");
    }

    #[test]
    fn test_sanitize_filename_for_temp() {
        assert_eq!(sanitize_filename_for_temp("file.txt"), "file.txt");
        assert_eq!(sanitize_filename_for_temp("bad<>file"), "bad__file");
        assert_eq!(sanitize_filename_for_temp(".hidden"), "_hidden");
        assert_eq!(sanitize_filename_for_temp(""), "temp_file");
    }
}
