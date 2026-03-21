//! Builder pattern for I/O operations
//!
//! Provides the main entry point for atomic file operations with
//! configurable options.
//!
//! ## Design Philosophy
//!
//! - **Single entry point**: All I/O operations through one builder
//! - **Secure defaults**: All defaults are restrictive
//! - **Pure functions**: No logging, no side effects (Layer 1)
//! - **Fluent API**: Chain configuration methods
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crate::primitives::io::IoBuilder;
//!
//! // Simple write with secure defaults
//! IoBuilder::new()
//!     .write("/path/to/file", b"content")?;
//!
//! // Write with custom options
//! IoBuilder::for_secrets()
//!     .write("/path/to/secret", b"secret data")?;
//!
//! // Incremental writes
//! let mut writer = IoBuilder::for_logs()
//!     .writer("/path/to/log")?;
//! writer.write_all(b"line 1\n")?;
//! writer.write_all(b"line 2\n")?;
//! writer.commit()?;
//! ```

// Public API - will be used by FileWriter (Issue #111) and external code
#![allow(dead_code)]

use std::path::Path;

use super::atomic::{AtomicWriter, write_atomic};
use super::options::{SyncMode, WriteOptions};
use super::permissions::FileMode;
use crate::primitives::types::Problem;

/// Unified builder for atomic I/O operations
///
/// This is the primary fluent API for the primitives/io module.
/// All write operations are atomic (write-to-temp → sync → rename).
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::IoBuilder;
///
/// // Use presets for common scenarios
/// IoBuilder::for_secrets().write("/path/to/key", b"secret")?;
/// IoBuilder::for_logs().write("/path/to/log", b"entry\n")?;
/// IoBuilder::for_config().write("/path/to/config", b"setting=value")?;
///
/// // Custom configuration
/// IoBuilder::new()
///     .mode(FileMode::PRIVATE)
///     .sync(SyncMode::Full)
///     .no_overwrite()
///     .write("/path/to/file", b"data")?;
/// ```
#[derive(Debug, Clone, Copy)]
pub struct IoBuilder {
    options: WriteOptions,
}

impl Default for IoBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl IoBuilder {
    // =========================================================================
    // Constructors
    // =========================================================================

    /// Create new IoBuilder with secure defaults
    ///
    /// Defaults:
    /// - Mode: 0640 (owner write, group read)
    /// - Sync: Data (fsync on commit)
    /// - No symlink following
    /// - Overwrite allowed
    #[must_use]
    pub fn new() -> Self {
        Self {
            options: WriteOptions::default(),
        }
    }

    /// Create builder for log files
    ///
    /// - Mode: 0640 (owner write, group read)
    /// - Sync: Data (balance durability and performance)
    #[must_use]
    pub fn for_logs() -> Self {
        Self {
            options: WriteOptions::for_logs(),
        }
    }

    /// Create builder for secrets/keys
    ///
    /// - Mode: 0600 (owner only)
    /// - Sync: Full (ensure durability)
    #[must_use]
    pub fn for_secrets() -> Self {
        Self {
            options: WriteOptions::for_secrets(),
        }
    }

    /// Create builder for configuration files
    ///
    /// - Mode: 0640 (owner write, group read)
    /// - Sync: Full (ensure durability)
    /// - Preserve existing permissions
    #[must_use]
    pub fn for_config() -> Self {
        Self {
            options: WriteOptions::for_config(),
        }
    }

    /// Create builder for temporary/cache files
    ///
    /// - Mode: 0600 (owner only)
    /// - Sync: None (speed over durability)
    #[must_use]
    pub fn for_temp() -> Self {
        Self {
            options: WriteOptions::for_temp(),
        }
    }

    /// Create builder for uploaded files
    ///
    /// - Mode: 0640 (owner write, group read)
    /// - Sync: Data (reasonable durability)
    /// - No overwrite (prevent clobbering)
    #[must_use]
    pub fn for_uploads() -> Self {
        Self {
            options: WriteOptions::for_uploads(),
        }
    }

    // =========================================================================
    // Configuration methods (fluent API)
    // =========================================================================

    /// Set file permissions
    #[must_use]
    pub fn mode(mut self, mode: FileMode) -> Self {
        self.options.mode = mode;
        self
    }

    /// Set sync mode for durability
    #[must_use]
    pub fn sync(mut self, sync: SyncMode) -> Self {
        self.options.sync = sync;
        self
    }

    /// Allow following symlinks (insecure - use with caution)
    ///
    /// **Warning**: Enabling symlink following can enable symlink attacks.
    #[must_use]
    pub fn follow_symlinks(mut self) -> Self {
        self.options.follow_symlinks = true;
        self
    }

    /// Disable overwriting existing files
    #[must_use]
    pub fn no_overwrite(mut self) -> Self {
        self.options.overwrite = false;
        self
    }

    /// Enable overwriting existing files (default)
    #[must_use]
    pub fn overwrite(mut self) -> Self {
        self.options.overwrite = true;
        self
    }

    /// Preserve existing file permissions when overwriting
    #[must_use]
    pub fn preserve_permissions(mut self) -> Self {
        self.options.preserve_permissions = true;
        self
    }

    // =========================================================================
    // Terminal operations
    // =========================================================================

    /// Write data to a file atomically
    ///
    /// Uses the write-to-temp → sync → rename pattern to ensure
    /// the file is either completely written or not modified at all.
    ///
    /// # Errors
    ///
    /// Returns `Problem::Io` if:
    /// - The target directory doesn't exist
    /// - Permission denied
    /// - Disk full
    /// - File exists and `no_overwrite()` was called
    /// - Path is a symlink and `follow_symlinks()` was not called
    pub fn write(self, path: impl AsRef<Path>, data: &[u8]) -> Result<(), Problem> {
        write_atomic(path, data, self.options)
    }

    /// Create an atomic writer for incremental writes
    ///
    /// Unlike `write()`, this allows writing data in chunks.
    /// The file is only created when `commit()` is called.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use std::io::Write;
    ///
    /// let mut writer = IoBuilder::for_logs().writer("/path/to/log")?;
    /// writer.write_all(b"line 1\n")?;
    /// writer.write_all(b"line 2\n")?;
    /// writer.commit()?;  // File is created atomically
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `Problem::Io` if the writer cannot be created.
    pub fn writer(self, path: impl AsRef<Path>) -> Result<AtomicWriter, Problem> {
        AtomicWriter::new(path, self.options)
    }

    /// Get the current write options
    ///
    /// Useful for inspecting configuration or passing to other functions.
    #[must_use]
    pub fn options(&self) -> WriteOptions {
        self.options
    }

    // =========================================================================
    // Async operations
    // =========================================================================

    /// Write data to a file atomically (async version)
    ///
    /// This wraps the synchronous `write()` in `spawn_blocking` from
    /// the `primitives/runtime` module, propagating the current context.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// IoBuilder::for_secrets()
    ///     .write_async("/path/to/secret".into(), b"data".to_vec())
    ///     .await?;
    /// ```
    ///
    /// # Note
    ///
    /// Requires the tokio runtime. For non-async code, use `write()` directly.
    pub async fn write_async(self, path: std::path::PathBuf, data: Vec<u8>) -> Result<(), Problem> {
        crate::primitives::runtime::r#async::spawn_blocking(move || {
            write_atomic(&path, &data, self.options)
        })
        .await
        .map_err(|e| Problem::io(format!("Async write failed: {}", e)))?
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_builder_default() {
        let builder = IoBuilder::new();
        let opts = builder.options();

        assert_eq!(opts.mode, FileMode::PRIVATE_GROUP_READ);
        assert_eq!(opts.sync, SyncMode::Data);
        assert!(!opts.follow_symlinks);
        assert!(opts.overwrite);
    }

    #[test]
    fn test_builder_presets() {
        let secrets = IoBuilder::for_secrets().options();
        assert_eq!(secrets.mode, FileMode::PRIVATE);
        assert_eq!(secrets.sync, SyncMode::Full);

        let logs = IoBuilder::for_logs().options();
        assert_eq!(logs.mode, FileMode::LOG_FILE);

        let config = IoBuilder::for_config().options();
        assert!(config.preserve_permissions);

        let uploads = IoBuilder::for_uploads().options();
        assert!(!uploads.overwrite);
    }

    #[test]
    fn test_builder_fluent_api() {
        let opts = IoBuilder::new()
            .mode(FileMode::PRIVATE)
            .sync(SyncMode::Full)
            .no_overwrite()
            .preserve_permissions()
            .options();

        assert_eq!(opts.mode, FileMode::PRIVATE);
        assert_eq!(opts.sync, SyncMode::Full);
        assert!(!opts.overwrite);
        assert!(opts.preserve_permissions);
    }

    #[test]
    fn test_builder_write() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");

        IoBuilder::new()
            .write(&path, b"hello world")
            .expect("write should succeed");

        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "hello world");
    }

    #[test]
    fn test_builder_writer() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("writer_test.txt");

        {
            let mut writer = IoBuilder::new().writer(&path).expect("create writer");

            writer.write_all(b"line 1\n").expect("write line 1");
            writer.write_all(b"line 2\n").expect("write line 2");
            writer.commit().expect("commit");
        }

        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "line 1\nline 2\n");
    }

    #[test]
    fn test_builder_no_overwrite() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("existing.txt");

        // Create initial file
        std::fs::write(&path, "original").expect("create file");

        // Try to overwrite with no_overwrite
        let result = IoBuilder::new().no_overwrite().write(&path, b"updated");

        assert!(result.is_err());

        // Original should be unchanged
        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "original");
    }

    #[cfg(unix)]
    #[test]
    fn test_builder_sets_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("perms.txt");

        IoBuilder::for_secrets()
            .write(&path, b"secret")
            .expect("write");

        let metadata = std::fs::metadata(&path).expect("get metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_builder_overwrite_toggle() {
        let opts = IoBuilder::new().no_overwrite().overwrite().options();
        assert!(opts.overwrite);
    }
}
