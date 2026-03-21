//! Filesystem Test Fixtures
//!
//! Provides temporary directories and files with various configurations
//! for testing filesystem operations.

// Allow missing docs for rstest fixture-generated types
#![allow(missing_docs)]

use assert_fs::TempDir;
use rstest::fixture;
use std::fs;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Basic temporary directory fixture
///
/// Creates an empty temporary directory that is automatically cleaned up
/// when the test completes (success or failure).
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::prelude::*;
///
/// #[rstest]
/// fn my_test(temp_dir: TempDir) {
///     let file = temp_dir.path().join("test.txt");
///     std::fs::write(&file, "hello").unwrap();
///     assert!(file.exists());
/// }
/// ```
#[fixture]
pub fn temp_dir() -> TempDir {
    TempDir::new().expect("Failed to create temp directory")
}

/// Temporary directory with a nested structure
///
/// Creates a temp directory with subdirectories for testing path operations.
///
/// # Structure
///
/// ```text
/// temp/
/// ├── subdir1/
/// │   └── nested/
/// ├── subdir2/
/// └── file.txt
/// ```
#[fixture]
pub fn nested_temp_dir() -> TempDir {
    let dir = TempDir::new().expect("Failed to create temp directory");

    fs::create_dir_all(dir.path().join("subdir1/nested"))
        .expect("Failed to create nested structure");
    fs::create_dir(dir.path().join("subdir2")).expect("Failed to create subdir2");
    fs::write(dir.path().join("file.txt"), "test content").expect("Failed to write file");

    dir
}

/// Read-only directory fixture (Unix only)
///
/// Creates a temporary directory with no write permissions.
/// Useful for testing permission denied scenarios.
///
/// # Note
///
/// The fixture restores write permissions before cleanup to allow
/// the temporary directory to be deleted.
#[cfg(unix)]
#[fixture]
pub fn readonly_dir() -> ReadonlyDir {
    let dir = TempDir::new().expect("Failed to create temp directory");

    // Create a file before making it read-only
    fs::write(dir.path().join("existing.txt"), "readonly content")
        .expect("Failed to write initial file");

    // Remove write permissions
    let metadata = fs::metadata(dir.path()).expect("Failed to get metadata");
    let mut perms = metadata.permissions();
    perms.set_mode(0o555); // r-xr-xr-x
    fs::set_permissions(dir.path(), perms).expect("Failed to set permissions");

    ReadonlyDir { inner: dir }
}

/// Wrapper for readonly directory that restores permissions on drop
#[cfg(unix)]
pub struct ReadonlyDir {
    inner: TempDir,
}

#[cfg(unix)]
impl ReadonlyDir {
    /// Get the path to the readonly directory
    pub fn path(&self) -> &std::path::Path {
        self.inner.path()
    }
}

#[cfg(unix)]
impl Drop for ReadonlyDir {
    fn drop(&mut self) {
        // Restore write permissions so cleanup can succeed
        if let Ok(metadata) = fs::metadata(self.inner.path()) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            let _ = fs::set_permissions(self.inner.path(), perms);
        }
    }
}

/// Directory with various symlink scenarios
///
/// Creates a temp directory with:
/// - Regular symlink to a file
/// - Symlink to a directory
/// - Broken symlink (target doesn't exist)
/// - Symlink loop (a → b → a)
///
/// # Structure
///
/// ```text
/// temp/
/// ├── real_file.txt        # Regular file
/// ├── real_dir/            # Regular directory
/// │   └── inside.txt
/// ├── link_to_file         # Symlink → real_file.txt
/// ├── link_to_dir          # Symlink → real_dir/
/// ├── broken_link          # Symlink → nonexistent
/// ├── loop_a               # Symlink → loop_b
/// └── loop_b               # Symlink → loop_a
/// ```
#[cfg(unix)]
#[fixture]
pub fn symlink_dir() -> TempDir {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().expect("Failed to create temp directory");
    let base = dir.path();

    // Create a regular file
    fs::write(base.join("real_file.txt"), "real content").expect("Failed to write file");

    // Create a directory
    fs::create_dir(base.join("real_dir")).expect("Failed to create directory");
    fs::write(base.join("real_dir/inside.txt"), "inside dir").expect("Failed to write file");

    // Symlink to file
    symlink(base.join("real_file.txt"), base.join("link_to_file"))
        .expect("Failed to create symlink");

    // Symlink to directory
    symlink(base.join("real_dir"), base.join("link_to_dir")).expect("Failed to create symlink");

    // Broken symlink (target doesn't exist)
    symlink(base.join("nonexistent"), base.join("broken_link"))
        .expect("Failed to create broken symlink");

    // Symlink loop: a → b → a
    symlink(base.join("loop_b"), base.join("loop_a")).expect("Failed to create loop_a");
    symlink(base.join("loop_a"), base.join("loop_b")).expect("Failed to create loop_b");

    dir
}

/// Temporary file with specific content
///
/// # Arguments
///
/// * `content` - The content to write to the file (default: "test content")
///
/// # Returns
///
/// A tuple of (TempDir, PathBuf) where PathBuf is the path to the created file.
/// Keep the TempDir alive to prevent cleanup.
#[fixture]
pub fn temp_file_with_content(#[default("test content")] content: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("Failed to create temp directory");
    let file_path = dir.path().join("test_file.txt");
    fs::write(&file_path, content).expect("Failed to write content");
    (dir, file_path)
}

/// Multiple temporary files for concurrent access testing
///
/// # Arguments
///
/// * `count` - Number of files to create (default: 5)
///
/// # Returns
///
/// A tuple of `(TempDir, Vec<PathBuf>)` containing paths to all created files.
#[fixture]
pub fn concurrent_test_files(#[default(5)] count: usize) -> (TempDir, Vec<PathBuf>) {
    let dir = TempDir::new().expect("Failed to create temp directory");
    let files: Vec<_> = (0..count)
        .map(|i| {
            let path = dir.path().join(format!("file_{}.txt", i));
            fs::write(&path, format!("content {}", i)).expect("Failed to write file");
            path
        })
        .collect();
    (dir, files)
}

/// Directory with files of various sizes for testing size limits
///
/// Creates files of 1KB, 10KB, 100KB, and 1MB for testing size-related operations.
#[fixture]
pub fn sized_files_dir() -> TempDir {
    let dir = TempDir::new().expect("Failed to create temp directory");

    let sizes = [
        ("tiny.txt", 1024),         // 1 KB
        ("small.txt", 10 * 1024),   // 10 KB
        ("medium.txt", 100 * 1024), // 100 KB
        ("large.txt", 1024 * 1024), // 1 MB
    ];

    for (name, size) in sizes {
        let content = "x".repeat(size);
        fs::write(dir.path().join(name), content).expect("Failed to write sized file");
    }

    dir
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[rstest::rstest]
    fn test_temp_dir_fixture(temp_dir: TempDir) {
        assert!(temp_dir.path().exists());
        assert!(temp_dir.path().is_dir());
    }

    #[rstest::rstest]
    fn test_nested_temp_dir_fixture(nested_temp_dir: TempDir) {
        assert!(nested_temp_dir.path().join("subdir1/nested").exists());
        assert!(nested_temp_dir.path().join("subdir2").exists());
        assert!(nested_temp_dir.path().join("file.txt").exists());
    }

    #[cfg(unix)]
    #[rstest::rstest]
    fn test_readonly_dir_fixture(readonly_dir: ReadonlyDir) {
        // Should have an existing file
        assert!(readonly_dir.path().join("existing.txt").exists());

        // Writing should fail - unless running as root (common in CI containers)
        // Root can write to any file regardless of permissions
        let result = fs::write(readonly_dir.path().join("new.txt"), "data");
        let is_root = nix::unistd::geteuid().is_root();
        if is_root {
            // Root bypasses permission checks, so write may succeed
            // Just verify the test ran without panicking
        } else {
            assert!(
                result.is_err(),
                "Non-root user should not be able to write to readonly dir"
            );
        }
    }

    #[cfg(unix)]
    #[rstest::rstest]
    fn test_symlink_dir_fixture(symlink_dir: TempDir) {
        let base = symlink_dir.path();

        // Regular symlink works
        assert!(base.join("link_to_file").exists());
        assert!(fs::read_link(base.join("link_to_file")).is_ok());

        // Directory symlink works
        assert!(base.join("link_to_dir").exists());
        assert!(base.join("link_to_dir/inside.txt").exists());

        // Broken symlink: symlink_metadata succeeds but exists() returns false
        assert!(fs::symlink_metadata(base.join("broken_link")).is_ok());
        assert!(!base.join("broken_link").exists());

        // Symlink loop exists
        assert!(fs::symlink_metadata(base.join("loop_a")).is_ok());
    }

    #[rstest::rstest]
    fn test_sized_files(sized_files_dir: TempDir) {
        let tiny = sized_files_dir.path().join("tiny.txt");
        let large = sized_files_dir.path().join("large.txt");

        assert!(tiny.exists());
        assert!(large.exists());

        let tiny_size = fs::metadata(&tiny)
            .expect("Failed to get tiny file metadata")
            .len();
        let large_size = fs::metadata(&large)
            .expect("Failed to get large file metadata")
            .len();

        assert_eq!(tiny_size, 1024);
        assert_eq!(large_size, 1024 * 1024);
    }
}
