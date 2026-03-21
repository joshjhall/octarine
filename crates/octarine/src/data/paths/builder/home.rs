//! Home directory operations builder with observability
//!
//! Provides home directory expansion and collapse operations.
//!
//! # Examples
//!
//! ```rust
//! use octarine::data::paths::HomeBuilder;
//!
//! let home = HomeBuilder::new();
//!
//! // Expansion
//! let expanded = home.expand("~/Documents").unwrap();
//! assert!(expanded.ends_with("/Documents"));
//!
//! // Detection
//! assert!(home.is_reference_present("~/path"));
//! ```

use crate::observe::Problem;
use crate::observe::metrics::increment;

use super::super::home;

crate::define_metrics! {
    expanded => "data.paths.home.expanded",
    collapsed => "data.paths.home.collapsed",
}

/// Home directory operations builder with observability
///
/// Provides home directory expansion and collapse with audit trail.
#[derive(Debug, Clone, Default)]
pub struct HomeBuilder {
    emit_events: bool,
}

impl HomeBuilder {
    /// Create a new home builder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self { emit_events: true }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self { emit_events: false }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // ========================================================================
    // Detection
    // ========================================================================

    /// Check if a path contains a home directory reference (~)
    #[must_use]
    pub fn is_reference_present(&self, path: &str) -> bool {
        home::is_home_reference_present(path)
    }

    // ========================================================================
    // Expansion
    // ========================================================================

    /// Expand ~ to the user's home directory
    ///
    /// Returns an error if:
    /// - The home directory cannot be determined
    /// - The path contains dangerous patterns after ~
    ///
    /// # Examples
    ///
    /// ```rust
    /// use octarine::data::paths::HomeBuilder;
    /// let home = HomeBuilder::new();
    /// let expanded = home.expand("~/Documents").unwrap();
    /// // Returns something like "/home/user/Documents"
    /// assert!(expanded.ends_with("/Documents"));
    /// ```
    pub fn expand(&self, path: &str) -> Result<String, Problem> {
        let result = home::expand_home(path);
        if self.emit_events && result.is_ok() {
            increment(metric_names::expanded());
        }
        result
    }

    // ========================================================================
    // Collapse
    // ========================================================================

    /// Collapse the home directory to ~
    ///
    /// If the path starts with the user's home directory, replaces it with ~.
    /// Always returns a valid path (lenient operation).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use octarine::data::paths::HomeBuilder;
    /// let home = HomeBuilder::new();
    /// // Collapse works when path matches actual home directory
    /// let collapsed = home.collapse("/nonexistent/path");
    /// // Returns original path if not under home dir
    /// ```
    #[must_use]
    pub fn collapse(&self, path: &str) -> String {
        let result = home::collapse_home(path);
        if self.emit_events {
            increment(metric_names::collapsed());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = HomeBuilder::new();
        assert!(builder.emit_events);

        let silent = HomeBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = HomeBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_home_detection() {
        let home = HomeBuilder::silent();

        assert!(home.is_reference_present("~"));
        assert!(home.is_reference_present("~/"));
        assert!(home.is_reference_present("~/path"));
        assert!(home.is_reference_present("~/.config"));
        assert!(!home.is_reference_present("/home/user"));
        assert!(!home.is_reference_present("relative/path"));
    }

    #[test]
    fn test_expand_no_tilde() {
        let home = HomeBuilder::silent();

        assert_eq!(home.expand("/etc/passwd").expect("no tilde"), "/etc/passwd");
        assert_eq!(
            home.expand("relative/path").expect("no tilde"),
            "relative/path"
        );
    }

    #[test]
    fn test_expand_rejects_traversal() {
        let home = HomeBuilder::silent();

        assert!(home.expand("~/../etc/passwd").is_err());
        assert!(home.expand("~/path/../../../etc").is_err());
    }

    #[test]
    fn test_expand_rejects_username_syntax() {
        let home = HomeBuilder::silent();

        assert!(home.expand("~otheruser/path").is_err());
    }

    #[test]
    fn test_collapse_no_change() {
        let home = HomeBuilder::silent();

        assert_eq!(home.collapse("/etc/passwd"), "/etc/passwd");
        assert_eq!(home.collapse("relative/path"), "relative/path");
    }
}
