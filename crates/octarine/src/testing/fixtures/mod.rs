//! Test Fixtures
//!
//! Reusable test fixtures using rstest. These provide common test setups
//! that are automatically cleaned up after each test.
//!
//! ## Available Fixtures
//!
//! ### Filesystem Fixtures
//! - [`temp_dir()`] - Empty temporary directory
//! - [`nested_temp_dir()`] - Directory with nested structure
//! - [`readonly_dir()`] - Directory with no write permissions
//! - [`symlink_dir()`] - Directory with various symlink scenarios
//!
//! `readonly_dir()` and `symlink_dir()` are available on both Unix and
//! Windows, but their platform semantics differ (directory read-only is
//! advisory on Windows; Windows symlinks need
//! `SeCreateSymbolicLinkPrivilege`). See each fixture's `# Platform Behavior`
//! section before asserting against them.
//!
//! ### File Fixtures
//! - [`temp_file_with_content()`] - Temporary file with specific content
//! - [`concurrent_test_files()`] - Multiple files for concurrency testing
//!
//! ## Usage
//!
//! ```rust,ignore
//! use octarine::testing::prelude::*;
//!
//! #[rstest]
//! fn test_with_temp_dir(temp_dir: TempDir) {
//!     let path = temp_dir.path().join("test.txt");
//!     std::fs::write(&path, "hello").unwrap();
//!     assert!(path.exists());
//! }
//! ```

mod filesystem;
mod network_fs;

pub use filesystem::*;
pub use network_fs::*;
