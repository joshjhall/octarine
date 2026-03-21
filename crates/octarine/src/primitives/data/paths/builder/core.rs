//! PathBuilder core struct and constructors
//!
//! Provides the main entry point for all path operations.

use super::super::types::Platform;

/// Unified builder for all path operations
///
/// This is the primary API for the primitives/paths module.
/// All methods delegate to specialized domain modules.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::paths::PathBuilder;
///
/// let builder = PathBuilder::new();
///
/// // Check for security threats
/// if builder.is_traversal_present("../../../etc/passwd") {
///     println!("Path traversal detected!");
/// }
///
/// // Get path components
/// let parent = builder.find_parent("/home/user/file.txt");
/// assert_eq!(parent, Some("/home/user"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct PathBuilder {
    /// Default platform for operations (Auto = detect from path)
    pub platform: Platform,
}

impl PathBuilder {
    /// Create new PathBuilder with auto platform detection
    #[must_use]
    pub fn new() -> Self {
        Self {
            platform: Platform::Auto,
        }
    }

    /// Create PathBuilder for specific platform
    #[must_use]
    pub fn for_platform(platform: Platform) -> Self {
        Self { platform }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = PathBuilder::new();
        assert_eq!(builder.platform, Platform::Auto);

        let unix_builder = PathBuilder::for_platform(Platform::Unix);
        assert_eq!(unix_builder.platform, Platform::Unix);

        let windows_builder = PathBuilder::for_platform(Platform::Windows);
        assert_eq!(windows_builder.platform, Platform::Windows);
    }

    #[test]
    fn test_builder_default() {
        let builder = PathBuilder::default();
        assert_eq!(builder.platform, Platform::Auto);
    }

    #[test]
    fn test_builder_clone() {
        let builder = PathBuilder::for_platform(Platform::Unix);
        let cloned = builder.clone();
        assert_eq!(cloned.platform, Platform::Unix);
    }
}
