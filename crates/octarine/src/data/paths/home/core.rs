//! Core home directory operations
//!
//! Implementation of home directory expansion and collapse.

use crate::observe::Problem;
use std::path::PathBuf;

/// Check if a path contains a home directory reference (~)
pub(in crate::data::paths) fn is_home_reference_present(path: &str) -> bool {
    path.starts_with('~') || path.starts_with("~/")
}

/// Expand ~ to the user's home directory
///
/// Returns an error if:
/// - The home directory cannot be determined
/// - The path contains invalid patterns after ~
pub(in crate::data::paths) fn expand_home(path: &str) -> Result<String, Problem> {
    if !is_home_reference_present(path) {
        return Ok(path.to_string());
    }

    let home = get_home_dir()?;

    if path == "~" {
        return Ok(home);
    }

    if let Some(rest) = path.strip_prefix("~/") {
        // Validate the rest doesn't contain dangerous patterns
        if rest.contains("..") {
            return Err(Problem::validation(
                "Path traversal not allowed after home expansion",
            ));
        }
        Ok(format!("{}/{}", home, rest))
    } else if path.starts_with("~") {
        // ~username syntax - not supported, return error
        Err(Problem::validation(
            "~username syntax not supported; use ~/path instead",
        ))
    } else {
        Ok(path.to_string())
    }
}

/// Collapse the home directory to ~
///
/// If the path starts with the user's home directory, replace it with ~.
/// Always returns a valid path (lenient operation).
pub(in crate::data::paths) fn collapse_home(path: &str) -> String {
    let home = match get_home_dir() {
        Ok(h) => h,
        Err(_) => return path.to_string(),
    };

    if path == home {
        return "~".to_string();
    }

    // Check if path starts with home directory
    let home_with_sep = format!("{}/", home);
    if let Some(rest) = path.strip_prefix(&home_with_sep) {
        format!("~/{}", rest)
    } else {
        path.to_string()
    }
}

/// Get the user's home directory
fn get_home_dir() -> Result<String, Problem> {
    // Try std::env::var first (works on most systems)
    if let Ok(home) = std::env::var("HOME")
        && !home.is_empty()
    {
        return Ok(home);
    }

    // Try USERPROFILE for Windows
    if let Ok(home) = std::env::var("USERPROFILE")
        && !home.is_empty()
    {
        return Ok(home);
    }

    // Try dirs crate fallback via std::path
    if let Some(home) = home_dir_fallback() {
        return Ok(home);
    }

    Err(Problem::validation("Could not determine home directory"))
}

/// Fallback home directory detection
fn home_dir_fallback() -> Option<String> {
    // Use a simple platform-specific fallback
    #[cfg(unix)]
    {
        // On Unix, try /etc/passwd via getpwuid
        // For simplicity, we'll just check common paths
        if let Ok(user) = std::env::var("USER") {
            let path = PathBuf::from(format!("/home/{}", user));
            if path.exists() {
                return Some(path.to_string_lossy().to_string());
            }
            // macOS uses /Users
            let path = PathBuf::from(format!("/Users/{}", user));
            if path.exists() {
                return Some(path.to_string_lossy().to_string());
            }
        }
    }

    #[cfg(windows)]
    {
        // Try common Windows paths
        if let (Ok(drive), Ok(user)) = (std::env::var("HOMEDRIVE"), std::env::var("HOMEPATH")) {
            return Some(format!("{}{}", drive, user));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_home_reference_present() {
        assert!(is_home_reference_present("~"));
        assert!(is_home_reference_present("~/"));
        assert!(is_home_reference_present("~/path"));
        assert!(is_home_reference_present("~/.config"));
        assert!(!is_home_reference_present("/home/user"));
        assert!(!is_home_reference_present("relative/path"));
        assert!(!is_home_reference_present("path/with~tilde"));
    }

    #[test]
    fn test_expand_home_no_tilde() {
        assert_eq!(expand_home("/etc/passwd").expect("no tilde"), "/etc/passwd");
        assert_eq!(
            expand_home("relative/path").expect("no tilde"),
            "relative/path"
        );
    }

    #[test]
    fn test_expand_home_rejects_traversal() {
        assert!(expand_home("~/../etc/passwd").is_err());
        assert!(expand_home("~/path/../../../etc").is_err());
    }

    #[test]
    fn test_expand_home_rejects_username_syntax() {
        assert!(expand_home("~otheruser/path").is_err());
    }

    #[test]
    fn test_collapse_home_no_change() {
        assert_eq!(collapse_home("/etc/passwd"), "/etc/passwd");
        assert_eq!(collapse_home("relative/path"), "relative/path");
    }
}
