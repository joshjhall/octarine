//! Async filesystem operations
//!
//! Provides async-first wrappers for common filesystem operations using `tokio::fs`.
//! All async operations use tokio's async filesystem API, which internally uses
//! `spawn_blocking` but provides a cleaner, more idiomatic interface.
//!
//! ## Philosophy: Async-First Design
//!
//! Like Node.js, we default to async operations. Blocking variants exist but
//! require explicit opt-in with `_sync` suffix.
//!
//! ```rust,ignore
//! // Async (default) - won't block the runtime
//! if path_exists(&path).await? {
//!     let metadata = path_metadata(&path).await?;
//! }
//!
//! // Sync (explicit opt-in) - WILL block the current thread
//! if path_exists_sync(&path)? {
//!     let metadata = path_metadata_sync(&path)?;
//! }
//! ```
//!
//! ## Why Async by Default?
//!
//! 1. **Observability Safety**: The `observe` module cannot block the main thread
//! 2. **Scalability**: Async operations allow other tasks to run during I/O
//! 3. **Consistency**: All I/O operations behave the same way
//! 4. **Predictability**: No hidden blocking in async contexts
//!
//! ## Implementation Note
//!
//! This module uses `tokio::fs` which provides async filesystem operations.
//! Under the hood, tokio::fs uses `spawn_blocking` to avoid blocking the async
//! runtime, but this is an implementation detail that may change in the future
//! (e.g., with io_uring support).

// Allow dead code - these are public API functions that will be used by external code
// and internal modules as the async-first design is adopted
#![allow(dead_code)]

use crate::primitives::types::Problem;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

// =============================================================================
// Error Mapping Helpers
// =============================================================================

/// Map an `std::io::Error` to a `Problem` with context about the path
fn map_io_error(e: std::io::Error, path: &Path) -> Problem {
    match e.kind() {
        std::io::ErrorKind::NotFound => Problem::not_found(format!("Path not found: {:?}", path)),
        std::io::ErrorKind::PermissionDenied => {
            Problem::io(format!("Permission denied: {:?}", path))
        }
        std::io::ErrorKind::InvalidData => Problem::io(format!("Invalid data in file: {:?}", path)),
        _ => Problem::io(format!("I/O error on {:?}: {}", path, e)),
    }
}

/// Map an `std::io::Error` to a `Problem` for operations involving two paths
fn map_io_error_two_paths(e: std::io::Error, from: &Path, to: &Path) -> Problem {
    match e.kind() {
        std::io::ErrorKind::NotFound => Problem::not_found(format!("Source not found: {:?}", from)),
        std::io::ErrorKind::PermissionDenied => {
            Problem::io(format!("Permission denied: {:?} -> {:?}", from, to))
        }
        _ => Problem::io(format!("I/O error {:?} -> {:?}: {}", from, to, e)),
    }
}

// =============================================================================
// Async Path Operations (Default)
// =============================================================================

/// Check if a path exists (async)
///
/// This is the async-first wrapper for checking path existence using `tokio::fs`.
/// Use this in async contexts to avoid blocking the runtime.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::path_exists;
///
/// async fn check_config() {
///     if path_exists("/etc/myapp/config.toml").await.unwrap_or(false) {
///         // Config exists
///     }
/// }
/// ```
///
/// # Errors
///
/// Returns `Ok(false)` if the path doesn't exist. Only returns error for
/// unexpected I/O failures.
pub async fn path_exists(path: impl AsRef<Path>) -> Result<bool, Problem> {
    // tokio::fs::try_exists returns Ok(true) if exists, Ok(false) if not,
    // and Err only for actual I/O errors (not "not found")
    let path = path.as_ref();
    tokio::fs::try_exists(path)
        .await
        .map_err(|e| map_io_error(e, path))
}

/// Get metadata for a path (async)
///
/// Async wrapper for `tokio::fs::metadata()`. Returns file metadata including
/// size, modification time, and permissions.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::path_metadata;
///
/// async fn check_file_size(path: &Path) -> Result<u64, Problem> {
///     let metadata = path_metadata(path).await?;
///     Ok(metadata.len())
/// }
/// ```
///
/// # Errors
///
/// Returns `Problem::NotFound` if the path doesn't exist, or `Problem::Io` for
/// other I/O errors.
pub async fn path_metadata(path: impl AsRef<Path>) -> Result<std::fs::Metadata, Problem> {
    let path = path.as_ref();
    tokio::fs::metadata(path)
        .await
        .map_err(|e| map_io_error(e, path))
}

/// Get symlink metadata for a path (async)
///
/// Like `path_metadata()` but doesn't follow symlinks - returns metadata
/// about the symlink itself rather than the target.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::symlink_metadata;
///
/// async fn is_symlink(path: &Path) -> bool {
///     symlink_metadata(path)
///         .await
///         .map(|m| m.file_type().is_symlink())
///         .unwrap_or(false)
/// }
/// ```
pub async fn symlink_metadata(path: impl AsRef<Path>) -> Result<std::fs::Metadata, Problem> {
    let path = path.as_ref();
    tokio::fs::symlink_metadata(path)
        .await
        .map_err(|e| map_io_error(e, path))
}

/// Check if a path is a file (async)
///
/// Convenience wrapper that returns true if the path exists and is a regular file.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::is_file;
///
/// async fn validate_config(path: &Path) -> Result<(), Problem> {
///     if !is_file(path).await? {
///         return Err(Problem::validation("Config must be a file"));
///     }
///     Ok(())
/// }
/// ```
pub async fn is_file(path: impl AsRef<Path>) -> Result<bool, Problem> {
    match path_metadata(path).await {
        Ok(metadata) => Ok(metadata.is_file()),
        Err(e) if e.to_string().contains("not found") => Ok(false),
        Err(e) => Err(e),
    }
}

/// Check if a path is a directory (async)
///
/// Convenience wrapper that returns true if the path exists and is a directory.
pub async fn is_dir(path: impl AsRef<Path>) -> Result<bool, Problem> {
    match path_metadata(path).await {
        Ok(metadata) => Ok(metadata.is_dir()),
        Err(e) if e.to_string().contains("not found") => Ok(false),
        Err(e) => Err(e),
    }
}

/// Check if a path is a symlink (async)
///
/// Convenience wrapper that returns true if the path exists and is a symbolic link.
pub async fn is_symlink(path: impl AsRef<Path>) -> Result<bool, Problem> {
    match symlink_metadata(path).await {
        Ok(metadata) => Ok(metadata.file_type().is_symlink()),
        Err(e) if e.to_string().contains("not found") => Ok(false),
        Err(e) => Err(e),
    }
}

/// Get the canonical path (async)
///
/// Resolves symlinks and returns the absolute canonical path.
/// Fails if the path doesn't exist.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::canonicalize;
///
/// async fn get_real_path(path: &Path) -> Result<PathBuf, Problem> {
///     canonicalize(path).await
/// }
/// ```
pub async fn canonicalize(path: impl AsRef<Path>) -> Result<PathBuf, Problem> {
    let path = path.as_ref();
    tokio::fs::canonicalize(path)
        .await
        .map_err(|e| map_io_error(e, path))
}

/// Read a directory (async)
///
/// Returns a vector of paths for entries in the directory.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::read_dir;
///
/// async fn list_logs(dir: &Path) -> Result<Vec<PathBuf>, Problem> {
///     read_dir(dir).await
/// }
/// ```
pub async fn read_dir(path: impl AsRef<Path>) -> Result<Vec<PathBuf>, Problem> {
    let path = path.as_ref();
    let mut read_dir = tokio::fs::read_dir(path)
        .await
        .map_err(|e| map_io_error(e, path))?;

    let mut entries = Vec::new();
    while let Some(entry) = read_dir
        .next_entry()
        .await
        .map_err(|e| map_io_error(e, path))?
    {
        entries.push(entry.path());
    }

    Ok(entries)
}

/// Get the modification time of a path (async)
///
/// Convenience wrapper that returns the modification time directly.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::modified_time;
///
/// async fn is_stale(path: &Path, max_age: Duration) -> Result<bool, Problem> {
///     let mtime = modified_time(path).await?;
///     let age = SystemTime::now().duration_since(mtime).unwrap_or_default();
///     Ok(age > max_age)
/// }
/// ```
pub async fn modified_time(path: impl AsRef<Path>) -> Result<SystemTime, Problem> {
    let metadata = path_metadata(path).await?;
    metadata
        .modified()
        .map_err(|e| Problem::operation_failed(format!("Failed to get modification time: {}", e)))
}

/// Get the file size (async)
///
/// Convenience wrapper that returns the file size in bytes.
pub async fn file_size(path: impl AsRef<Path>) -> Result<u64, Problem> {
    let metadata = path_metadata(path).await?;
    Ok(metadata.len())
}

// =============================================================================
// Async File Operations
// =============================================================================

/// Remove a file (async)
///
/// Async wrapper for `tokio::fs::remove_file()`.
///
/// # Errors
///
/// Returns error if the file doesn't exist or can't be removed.
pub async fn remove_file(path: impl AsRef<Path>) -> Result<(), Problem> {
    let path = path.as_ref();
    tokio::fs::remove_file(path)
        .await
        .map_err(|e| map_io_error(e, path))
}

/// Rename/move a file or directory (async)
///
/// Async wrapper for `tokio::fs::rename()`.
pub async fn rename(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<(), Problem> {
    let from = from.as_ref();
    let to = to.as_ref();
    tokio::fs::rename(from, to)
        .await
        .map_err(|e| map_io_error_two_paths(e, from, to))
}

/// Copy a file (async)
///
/// Async wrapper for `tokio::fs::copy()`. Returns the number of bytes copied.
pub async fn copy_file(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<u64, Problem> {
    let from = from.as_ref();
    let to = to.as_ref();
    tokio::fs::copy(from, to)
        .await
        .map_err(|e| map_io_error_two_paths(e, from, to))
}

/// Create a directory and all parent directories (async)
///
/// Async wrapper for `tokio::fs::create_dir_all()`.
pub async fn create_dir_all(path: impl AsRef<Path>) -> Result<(), Problem> {
    let path = path.as_ref();
    tokio::fs::create_dir_all(path)
        .await
        .map_err(|e| map_io_error(e, path))
}

/// Read entire file contents (async)
///
/// Async wrapper for `tokio::fs::read()`. Returns the file contents as bytes.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::file::read_file;
///
/// async fn load_config(path: &Path) -> Result<Vec<u8>, Problem> {
///     read_file(path).await
/// }
/// ```
///
/// # Errors
///
/// Returns `Problem::NotFound` if the path doesn't exist, or `Problem::Io` for
/// other I/O errors.
pub async fn read_file(path: impl AsRef<Path>) -> Result<Vec<u8>, Problem> {
    let path = path.as_ref();
    tokio::fs::read(path)
        .await
        .map_err(|e| map_io_error(e, path))
}

/// Read entire file contents as a UTF-8 string (async)
///
/// Async wrapper for `tokio::fs::read_to_string()`.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::file::read_file_string;
///
/// async fn load_config(path: &Path) -> Result<String, Problem> {
///     read_file_string(path).await
/// }
/// ```
///
/// # Errors
///
/// Returns error if the file doesn't exist, can't be read, or contains invalid UTF-8.
pub async fn read_file_string(path: impl AsRef<Path>) -> Result<String, Problem> {
    let path = path.as_ref();
    tokio::fs::read_to_string(path)
        .await
        .map_err(|e| map_io_error(e, path))
}

/// Write data to a file (async)
///
/// Async wrapper for `tokio::fs::write()`. Creates the file if it doesn't exist,
/// or truncates it if it does.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::file::write_file;
///
/// async fn save_config(path: &Path, data: &[u8]) -> Result<(), Problem> {
///     write_file(path, data).await
/// }
/// ```
///
/// # Errors
///
/// Returns error if the file can't be created or written to.
pub async fn write_file(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> Result<(), Problem> {
    let path = path.as_ref();
    tokio::fs::write(path, contents)
        .await
        .map_err(|e| map_io_error(e, path))
}

/// Write string to a file (async)
///
/// Convenience wrapper that writes a string as UTF-8 bytes.
pub async fn write_file_string(path: impl AsRef<Path>, contents: &str) -> Result<(), Problem> {
    write_file(path, contents.as_bytes()).await
}

/// Read file contents (sync, blocking)
///
/// **Warning**: This WILL block the current thread.
#[inline]
pub fn read_file_sync(path: impl AsRef<Path>) -> Result<Vec<u8>, Problem> {
    let path = path.as_ref();
    std::fs::read(path).map_err(|e| map_io_error(e, path))
}

/// Read file as string (sync, blocking)
///
/// **Warning**: This WILL block the current thread.
#[inline]
pub fn read_file_string_sync(path: impl AsRef<Path>) -> Result<String, Problem> {
    let path = path.as_ref();
    std::fs::read_to_string(path).map_err(|e| map_io_error(e, path))
}

/// Write data to file (sync, blocking)
///
/// **Warning**: This WILL block the current thread.
#[inline]
pub fn write_file_sync(path: impl AsRef<Path>, contents: &[u8]) -> Result<(), Problem> {
    let path = path.as_ref();
    std::fs::write(path, contents).map_err(|e| map_io_error(e, path))
}

// =============================================================================
// Sync Variants (Explicit Opt-In)
// =============================================================================

/// Check if a path exists (sync, blocking)
///
/// **Warning**: This WILL block the current thread. Only use in:
/// - Tests
/// - Sync code paths
/// - Inside `spawn_blocking` (where blocking is expected)
///
/// For async contexts, use `path_exists()` instead.
#[inline]
pub fn path_exists_sync(path: impl AsRef<Path>) -> bool {
    path.as_ref().exists()
}

/// Get metadata for a path (sync, blocking)
///
/// **Warning**: This WILL block the current thread.
#[inline]
pub fn path_metadata_sync(path: impl AsRef<Path>) -> Result<std::fs::Metadata, Problem> {
    let path = path.as_ref();
    std::fs::metadata(path).map_err(|e| map_io_error(e, path))
}

/// Check if a path is a file (sync, blocking)
///
/// **Warning**: This WILL block the current thread.
#[inline]
pub fn is_file_sync(path: impl AsRef<Path>) -> bool {
    path.as_ref().is_file()
}

/// Check if a path is a directory (sync, blocking)
///
/// **Warning**: This WILL block the current thread.
#[inline]
pub fn is_dir_sync(path: impl AsRef<Path>) -> bool {
    path.as_ref().is_dir()
}

/// Get file size (sync, blocking)
///
/// **Warning**: This WILL block the current thread.
#[inline]
pub fn file_size_sync(path: impl AsRef<Path>) -> Result<u64, Problem> {
    let metadata = path_metadata_sync(path)?;
    Ok(metadata.len())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_path_exists_async() {
        let dir = tempdir().expect("create temp dir");
        let file_path = dir.path().join("test.txt");

        // File doesn't exist yet
        assert!(
            !path_exists(&file_path)
                .await
                .expect("path_exists should succeed")
        );

        // Create the file
        std::fs::write(&file_path, "hello").expect("write file");

        // Now it exists
        assert!(
            path_exists(&file_path)
                .await
                .expect("path_exists should succeed")
        );
    }

    #[tokio::test]
    async fn test_path_metadata_async() {
        let dir = tempdir().expect("create temp dir");
        let file_path = dir.path().join("test.txt");

        // Write some data
        std::fs::write(&file_path, "hello world").expect("write file");

        let metadata = path_metadata(&file_path).await.expect("get metadata");
        assert_eq!(metadata.len(), 11); // "hello world" is 11 bytes
        assert!(metadata.is_file());
    }

    #[tokio::test]
    async fn test_path_metadata_not_found() {
        let result = path_metadata(PathBuf::from("/nonexistent/path/file.txt")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_is_file_and_is_dir() {
        let dir = tempdir().expect("create temp dir");
        let file_path = dir.path().join("test.txt");

        std::fs::write(&file_path, "data").expect("write file");

        // Check file
        assert!(is_file(&file_path).await.expect("is_file should succeed"));
        assert!(!is_dir(&file_path).await.expect("is_dir should succeed"));

        // Check directory
        assert!(is_dir(dir.path()).await.expect("is_dir should succeed"));
        assert!(!is_file(dir.path()).await.expect("is_file should succeed"));
    }

    #[tokio::test]
    async fn test_file_size_async() {
        let dir = tempdir().expect("create temp dir");
        let file_path = dir.path().join("test.txt");

        let content = "test content here";
        std::fs::write(&file_path, content).expect("write file");

        let size = file_size(&file_path).await.expect("get size");
        assert_eq!(size, content.len() as u64);
    }

    #[tokio::test]
    async fn test_remove_file_async() {
        let dir = tempdir().expect("create temp dir");
        let file_path = dir.path().join("to_delete.txt");

        std::fs::write(&file_path, "delete me").expect("write file");
        assert!(
            path_exists(&file_path)
                .await
                .expect("path_exists should succeed")
        );

        remove_file(&file_path).await.expect("remove file");
        assert!(
            !path_exists(&file_path)
                .await
                .expect("path_exists should succeed")
        );
    }

    #[tokio::test]
    async fn test_rename_async() {
        let dir = tempdir().expect("create temp dir");
        let old_path = dir.path().join("old.txt");
        let new_path = dir.path().join("new.txt");

        std::fs::write(&old_path, "content").expect("write file");

        rename(&old_path, &new_path).await.expect("rename");

        assert!(
            !path_exists(&old_path)
                .await
                .expect("path_exists should succeed")
        );
        assert!(
            path_exists(&new_path)
                .await
                .expect("path_exists should succeed")
        );
    }

    #[tokio::test]
    async fn test_create_dir_all_async() {
        let dir = tempdir().expect("create temp dir");
        let nested_path = dir.path().join("a").join("b").join("c");

        assert!(
            !path_exists(&nested_path)
                .await
                .expect("path_exists should succeed")
        );

        create_dir_all(&nested_path).await.expect("create dirs");

        assert!(
            path_exists(&nested_path)
                .await
                .expect("path_exists should succeed")
        );
        assert!(is_dir(&nested_path).await.expect("is_dir should succeed"));
    }

    #[tokio::test]
    async fn test_read_dir_async() {
        let dir = tempdir().expect("create temp dir");

        // Create some files
        std::fs::write(dir.path().join("file1.txt"), "1").expect("write");
        std::fs::write(dir.path().join("file2.txt"), "2").expect("write");
        std::fs::write(dir.path().join("file3.txt"), "3").expect("write");

        let entries = read_dir(dir.path()).await.expect("read dir");

        assert_eq!(entries.len(), 3);
    }

    #[tokio::test]
    async fn test_read_write_file_async() {
        let dir = tempdir().expect("create temp dir");
        let file_path = dir.path().join("readwrite.txt");

        let content = b"async file content";
        write_file(&file_path, content).await.expect("write file");

        let read_content = read_file(&file_path).await.expect("read file");
        assert_eq!(read_content, content);
    }

    #[tokio::test]
    async fn test_read_write_file_string_async() {
        let dir = tempdir().expect("create temp dir");
        let file_path = dir.path().join("string.txt");

        let content = "string content";
        write_file_string(&file_path, content)
            .await
            .expect("write string");

        let read_content = read_file_string(&file_path).await.expect("read string");
        assert_eq!(read_content, content);
    }

    #[test]
    fn test_sync_variants() {
        let dir = tempdir().expect("create temp dir");
        let file_path = dir.path().join("sync_test.txt");

        std::fs::write(&file_path, "sync content").expect("write file");

        assert!(path_exists_sync(&file_path));
        assert!(is_file_sync(&file_path));
        assert!(!is_dir_sync(&file_path));
        assert_eq!(
            file_size_sync(&file_path).expect("file_size_sync should succeed"),
            12
        );

        let metadata = path_metadata_sync(&file_path).expect("path_metadata_sync should succeed");
        assert!(metadata.is_file());
    }

    #[tokio::test]
    async fn test_copy_file_async() {
        let dir = tempdir().expect("create temp dir");
        let src = dir.path().join("source.txt");
        let dst = dir.path().join("dest.txt");

        let content = "copy this content";
        std::fs::write(&src, content).expect("write source");

        let bytes_copied = copy_file(&src, &dst).await.expect("copy file");
        assert_eq!(bytes_copied, content.len() as u64);

        let copied_content = std::fs::read_to_string(&dst).expect("read dest");
        assert_eq!(copied_content, content);
    }
}
