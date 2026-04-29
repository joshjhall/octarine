//! Path construction delegators for [`PathBuilder`].
//!
//! Low-level path manipulation methods that delegate to the primitive
//! [`PrimitivePathBuilder`] for joining, splitting, and resolving paths.

use super::super::PathBuilder;
use crate::primitives::data::paths::PathBuilder as PrimitivePathBuilder;
use crate::primitives::data::paths::Platform as PrimitivePlatform;

impl PathBuilder {
    /// Join two path segments
    ///
    /// Uses the platform set via `for_platform()` or `Platform::Auto` by default.
    #[must_use]
    pub fn join(&self, base: &str, path: &str) -> String {
        let prim_platform: PrimitivePlatform = self.platform.into();
        PrimitivePathBuilder::for_platform(prim_platform).join(base, path)
    }

    /// Join paths with Unix separators
    #[must_use]
    pub fn join_unix(&self, base: &str, path: &str) -> String {
        PrimitivePathBuilder::new().join_unix(base, path)
    }

    /// Join paths with Windows separators
    #[must_use]
    pub fn join_windows(&self, base: &str, path: &str) -> String {
        PrimitivePathBuilder::new().join_windows(base, path)
    }

    /// Get parent directory
    #[must_use]
    pub fn find_parent<'a>(&self, path: &'a str) -> Option<&'a str> {
        PrimitivePathBuilder::new().find_parent(path)
    }

    /// Split path into components
    #[must_use]
    pub fn split<'a>(&self, path: &'a str) -> Vec<&'a str> {
        PrimitivePathBuilder::new().split(path)
    }

    /// Clean path by resolving . and .. components
    #[must_use]
    pub fn clean_path_components(&self, path: &str) -> String {
        PrimitivePathBuilder::new().clean_path(path)
    }

    /// Convert a relative path to absolute by resolving against a base
    #[must_use]
    pub fn to_absolute_path(&self, base: &str, path: &str) -> String {
        PrimitivePathBuilder::new().to_absolute_path(base, path)
    }

    /// Convert an absolute path to a relative path from one location to another
    #[must_use]
    pub fn to_relative_path(&self, from: &str, to: &str) -> String {
        PrimitivePathBuilder::new().to_relative_path(from, to)
    }
}
