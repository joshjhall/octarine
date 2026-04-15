//! Path construction utilities
//!
//! This module provides functions for building and manipulating paths:
//!
//! - **join**: Joining path segments together
//! - **components**: Extracting path parts (parent, filename, extension)
//! - **resolve**: Resolving relative paths and simplifying `.`/`..`
//!
//! # Design Principles
//!
//! 1. **Pure Functions**: No logging, no side effects
//! 2. **No Validation**: Construction does NOT validate for security
//! 3. **No Filesystem Access**: Works on strings only, no I/O
//! 4. **Platform-Aware**: Handles both Unix and Windows paths
//!
//! # Important: Construction vs Validation
//!
//! Construction functions handle **format** (separators, joining, splitting).
//! They do NOT check for security issues like:
//! - Directory traversal (`../..`)
//! - Command injection (`$(whoami)`)
//! - Null bytes
//!
//! Security validation should happen BEFORE passing input to construction
//! functions, or AFTER receiving output. This keeps concerns separated.
//!
//! # Example Usage
//!
//! ```ignore
//! use octarine::primitives::paths::common::construction::{join, components, resolve};
//!
//! // Join path segments
//! let path = join::join_unix("base/dir", "file.txt");
//! assert_eq!(path, "base/dir/file.txt");
//!
//! // Extract components
//! let parent = components::find_parent("path/to/file.txt");
//! let ext = components::find_extension("file.txt");
//!
//! // Clean paths (resolve . and ..)
//! let cleaned = resolve::clean_path("path/to/../other/./file");
//! assert_eq!(cleaned, "path/other/file");
//! ```

pub(crate) mod components;
pub(crate) mod join;
pub(crate) mod resolve;

// Re-export commonly used functions for convenience
// Note: Some items may be unused currently but are exported for future domain modules
#[allow(unused_imports)]
pub use components::{
    ancestors, depth, effective_depth, extensions, filename, find_extension, find_parent,
    is_extension_found, split, split_last, stem,
};
#[allow(unused_imports)]
pub use join::{
    join_if_relative, join_many_std, join_many_unix, join_many_windows, join_std, join_unix,
    join_windows,
};
#[allow(unused_imports)]
pub use resolve::{
    add_extension, clean_path, clean_path_std, to_absolute_path, to_relative_path, with_extension,
};

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    /// Integration test: full path manipulation workflow
    #[test]
    fn test_path_manipulation_workflow() {
        // Start with base path
        let base = "project/src";

        // Join with relative path
        let full = join_unix(base, "lib/../main.rs");
        assert_eq!(full, "project/src/lib/../main.rs");

        // Clean the path
        let cleaned = clean_path(&full);
        assert_eq!(cleaned, "project/src/main.rs");

        // Extract components
        assert_eq!(find_parent(&cleaned), Some("project/src"));
        assert_eq!(filename(&cleaned), "main.rs");
        assert_eq!(stem(&cleaned), "main");
        assert_eq!(find_extension(&cleaned), Some("rs"));

        // Change extension
        let with_new_ext = with_extension(&cleaned, "txt");
        assert_eq!(with_new_ext, "project/src/main.txt");
    }

    /// Test that construction preserves dangerous patterns
    /// (This is intentional - security is handled separately)
    #[test]
    fn test_preserves_dangerous_patterns() {
        // Traversal patterns are preserved
        let path = join_unix("base", "../../etc/passwd");
        assert!(path.contains(".."));

        // Injection patterns are preserved
        let path = join_unix("base", "$(whoami)");
        assert!(path.contains("$("));

        // These will be caught by the validation layer
        // Construction just handles format
    }

    /// Test cross-platform path handling
    #[test]
    fn test_cross_platform() {
        // Unix-style
        let unix_path = join_unix("path", "to/file");
        assert_eq!(unix_path, "path/to/file");

        // Windows-style
        let win_path = join_windows("path", "to\\file");
        assert_eq!(win_path, "path\\to\\file");

        // Components work with both
        assert_eq!(filename("path/to/file.txt"), "file.txt");
        assert_eq!(filename("path\\to\\file.txt"), "file.txt");
    }
}
