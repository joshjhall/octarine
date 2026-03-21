//! Secure temporary file management
//!
//! Provides secure temporary files with:
//! - Restrictive permissions (0600 by default)
//! - Automatic cleanup on drop
//! - Optional secure deletion (overwrite before delete)
//! - Audit trails via observe
//!
//! # Async-First Design
//!
//! This module follows the async-first design pattern. The primary API is async:
//!
//! ```ignore
//! use octarine::io::SecureTempFile;
//!
//! // Async (default)
//! let mut temp = SecureTempFile::new().await?;
//! temp.write_all(b"secret data")?;  // Write trait is sync
//! temp.delete().await?;
//!
//! // Sync (explicit opt-in)
//! let mut temp = SecureTempFile::new_sync()?;
//! temp.write_all(b"secret data")?;
//! temp.delete_sync()?;
//! ```
//!
//! Note: The `std::io::Write` trait implementation remains sync because that's
//! the standard Rust file I/O pattern. Use `tokio::io::AsyncWriteExt` for async
//! writes if needed.
//!
//! # Security Features
//!
//! - **Restrictive permissions**: Files are created with 0600 (owner read/write only)
//! - **No race conditions**: Uses platform-specific APIs to avoid TOCTOU issues
//! - **Secure deletion**: Optional multi-pass overwrite before deletion
//! - **Audit trails**: All operations logged for compliance

// Allow dead code - these are public APIs for library consumers
#![allow(dead_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::io::delete::{DeleteMethod, SecureDelete};
use crate::observe::{self, Problem};
use crate::primitives::io::file::FileMode;
use crate::primitives::runtime::r#async::spawn_blocking;

/// A secure temporary file with automatic cleanup
///
/// The file is created with restrictive permissions and automatically
/// deleted when dropped. Optionally supports secure deletion with
/// data overwriting.
///
/// # Examples
///
/// ```ignore
/// use octarine::io::SecureTempFile;
///
/// // Async (default)
/// let mut temp = SecureTempFile::builder()
///     .prefix("secret-")
///     .secure_delete(true)
///     .build().await?;
///
/// temp.write_all(b"sensitive data")?;
/// // File securely deleted on drop
///
/// // Sync (explicit opt-in)
/// let mut temp = SecureTempFile::builder()
///     .prefix("secret-")
///     .build_sync()?;
/// ```
pub struct SecureTempFile {
    path: PathBuf,
    file: Option<File>,
    secure_delete: bool,
    deleted: bool,
}

impl SecureTempFile {
    // =========================================================================
    // Async API (Default)
    // =========================================================================

    /// Create a new secure temp file in the system temp directory (async)
    ///
    /// The file is created with 0600 permissions (owner read/write only).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let temp = SecureTempFile::new().await?;
    /// ```
    pub async fn new() -> Result<Self, Problem> {
        SecureTempFileBuilder::new().build().await
    }

    /// Create a secure temp file at a specific path (async)
    ///
    /// Use this when you need the file at a known location (e.g., `.env` file).
    ///
    /// # Arguments
    ///
    /// * `path` - The path where the file should be created
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let temp = SecureTempFile::at_path("/app/.env.tmp").await?;
    /// ```
    pub async fn at_path(path: impl AsRef<Path>) -> Result<Self, Problem> {
        SecureTempFileBuilder::new().at_path(path).await
    }

    /// Delete the file explicitly (async)
    ///
    /// This is called automatically on drop, but you can call it manually
    /// if you need to handle errors.
    pub async fn delete(&mut self) -> Result<(), Problem> {
        if self.deleted {
            return Ok(());
        }

        // Close file handle first
        self.file.take();

        // Perform secure deletion if requested
        if self.secure_delete && self.path.exists() {
            // Use the Quick method for temp files (single random pass)
            // This is faster than DoD/NIST but still prevents casual recovery
            SecureDelete::new(&self.path)
                .await?
                .method(DeleteMethod::Quick)
                .execute()
                .await?;
        } else if self.path.exists() {
            let path = self.path.clone();
            spawn_blocking(move || {
                fs::remove_file(&path)
                    .map_err(|e| Problem::io(format!("Failed to delete temp file: {}", e)))
            })
            .await
            .map_err(|e| Problem::operation_failed(format!("Async delete failed: {}", e)))??;
        }

        self.deleted = true;
        observe::info(
            "io.temp.delete",
            format!(
                "Deleted temp file {} (secure={})",
                self.path.display(),
                self.secure_delete
            ),
        );

        Ok(())
    }

    // =========================================================================
    // Sync API (Explicit Opt-In)
    // =========================================================================

    /// Create a new secure temp file in the system temp directory (sync)
    ///
    /// **Warning**: This WILL block the current thread.
    ///
    /// The file is created with 0600 permissions (owner read/write only).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let temp = SecureTempFile::new_sync()?;
    /// ```
    pub fn new_sync() -> Result<Self, Problem> {
        SecureTempFileBuilder::new().build_sync()
    }

    /// Create a secure temp file at a specific path (sync)
    ///
    /// **Warning**: This WILL block the current thread.
    ///
    /// # Arguments
    ///
    /// * `path` - The path where the file should be created
    pub fn at_path_sync(path: impl AsRef<Path>) -> Result<Self, Problem> {
        SecureTempFileBuilder::new().at_path_sync(path)
    }

    /// Delete the file explicitly (sync)
    ///
    /// **Warning**: This WILL block the current thread.
    ///
    /// This is called automatically on drop, but you can call it manually
    /// if you need to handle errors.
    pub fn delete_sync(&mut self) -> Result<(), Problem> {
        if self.deleted {
            return Ok(());
        }

        // Close file handle first
        self.file.take();

        // Perform secure deletion if requested
        if self.secure_delete && self.path.exists() {
            // Use the Quick method for temp files (single random pass)
            // This is faster than DoD/NIST but still prevents casual recovery
            SecureDelete::new_sync(&self.path)?
                .method(DeleteMethod::Quick)
                .execute_sync()?;
        } else if self.path.exists() {
            fs::remove_file(&self.path)
                .map_err(|e| Problem::io(format!("Failed to delete temp file: {}", e)))?;
        }

        self.deleted = true;
        observe::info(
            "io.temp.delete",
            format!(
                "Deleted temp file {} (secure={})",
                self.path.display(),
                self.secure_delete
            ),
        );

        Ok(())
    }

    // =========================================================================
    // Shared API (works with both async and sync)
    // =========================================================================

    /// Create a builder for more control over temp file creation
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Async
    /// let temp = SecureTempFile::builder()
    ///     .prefix("myapp-")
    ///     .suffix(".tmp")
    ///     .in_dir("/secure/tmp")
    ///     .secure_delete(true)
    ///     .build().await?;
    ///
    /// // Sync
    /// let temp = SecureTempFile::builder()
    ///     .prefix("myapp-")
    ///     .build_sync()?;
    /// ```
    pub fn builder() -> SecureTempFileBuilder {
        SecureTempFileBuilder::new()
    }

    /// Get the path to the temporary file
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write data to the file
    ///
    /// Note: This is a sync operation because it uses `std::io::Write`.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to write
    ///
    /// # Examples
    ///
    /// ```ignore
    /// temp.write_all(b"secret data")?;
    /// ```
    pub fn write_all(&mut self, data: &[u8]) -> Result<(), Problem> {
        let file = self.file.as_mut().ok_or_else(|| {
            Problem::io("SecureTempFile: file handle is not available (already closed?)")
        })?;

        file.write_all(data)
            .map_err(|e| Problem::io(format!("Failed to write to temp file: {}", e)))?;

        observe::debug(
            "io.temp.write",
            format!("Wrote {} bytes to {}", data.len(), self.path.display()),
        );

        Ok(())
    }

    /// Sync the file to disk
    ///
    /// Ensures all data is persisted to storage.
    pub fn sync(&self) -> Result<(), Problem> {
        let file = self.file.as_ref().ok_or_else(|| {
            Problem::io("SecureTempFile: file handle is not available (already closed?)")
        })?;

        file.sync_all()
            .map_err(|e| Problem::io(format!("Failed to sync temp file: {}", e)))?;

        observe::debug("io.temp.sync", format!("Synced {}", self.path.display()));

        Ok(())
    }

    /// Close the file handle (but don't delete the file yet)
    ///
    /// Use this if you need to pass the file to another process that
    /// requires exclusive access.
    pub fn close(&mut self) -> Result<(), Problem> {
        if let Some(file) = self.file.take() {
            file.sync_all()
                .map_err(|e| Problem::io(format!("Failed to sync before close: {}", e)))?;
            drop(file);
            observe::debug("io.temp.close", format!("Closed {}", self.path.display()));
        }
        Ok(())
    }

    /// Check if secure deletion is enabled
    pub fn secure_delete_enabled(&self) -> bool {
        self.secure_delete
    }
}

impl Drop for SecureTempFile {
    fn drop(&mut self) {
        if !self.deleted
            && let Err(e) = self.delete_sync()
        {
            // Log but don't panic in drop
            observe::warn(
                "io.temp.drop",
                format!("Failed to delete temp file on drop: {}", e),
            );
        }
    }
}

impl Write for SecureTempFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("File handle not available"))?;
        file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("File handle not available"))?;
        file.flush()
    }
}

/// Builder for creating secure temporary files
pub struct SecureTempFileBuilder {
    prefix: String,
    suffix: String,
    dir: Option<PathBuf>,
    mode: FileMode,
    secure_delete: bool,
}

impl SecureTempFileBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self {
            prefix: String::new(),
            suffix: String::new(),
            dir: None,
            mode: FileMode::PRIVATE, // 0600
            secure_delete: false,
        }
    }

    /// Set the filename prefix
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let temp = SecureTempFile::builder()
    ///     .prefix("myapp-")
    ///     .build().await?;
    /// ```
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Set the filename suffix
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let temp = SecureTempFile::builder()
    ///     .suffix(".env")
    ///     .build().await?;
    /// ```
    pub fn suffix(mut self, suffix: impl Into<String>) -> Self {
        self.suffix = suffix.into();
        self
    }

    /// Set the directory for the temp file
    ///
    /// If not set, uses the system temp directory.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let temp = SecureTempFile::builder()
    ///     .in_dir("/secure/tmp")
    ///     .build().await?;
    /// ```
    pub fn in_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.dir = Some(dir.into());
        self
    }

    /// Set the file permissions
    ///
    /// Defaults to 0600 (owner read/write only).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let temp = SecureTempFile::builder()
    ///     .mode(FileMode::PRIVATE_GROUP_READ)
    ///     .build().await?;
    /// ```
    pub fn mode(mut self, mode: FileMode) -> Self {
        self.mode = mode;
        self
    }

    /// Enable secure deletion (overwrite before delete)
    ///
    /// When enabled, the file contents are overwritten with random data
    /// before deletion to prevent recovery.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let temp = SecureTempFile::builder()
    ///     .secure_delete(true)
    ///     .build().await?;
    /// ```
    pub fn secure_delete(mut self, enabled: bool) -> Self {
        self.secure_delete = enabled;
        self
    }

    // =========================================================================
    // Async Build Methods
    // =========================================================================

    /// Build the secure temp file (async)
    pub async fn build(self) -> Result<SecureTempFile, Problem> {
        let builder = self;
        spawn_blocking(move || builder.build_sync_impl())
            .await
            .map_err(|e| Problem::operation_failed(format!("Async build failed: {}", e)))?
    }

    /// Create the temp file at a specific path (async)
    pub async fn at_path(self, path: impl AsRef<Path>) -> Result<SecureTempFile, Problem> {
        let path = path.as_ref().to_path_buf();
        let builder = self;
        spawn_blocking(move || builder.create_at_path(path))
            .await
            .map_err(|e| Problem::operation_failed(format!("Async at_path failed: {}", e)))?
    }

    // =========================================================================
    // Sync Build Methods
    // =========================================================================

    /// Build the secure temp file (sync)
    ///
    /// **Warning**: This WILL block the current thread.
    pub fn build_sync(self) -> Result<SecureTempFile, Problem> {
        self.build_sync_impl()
    }

    /// Create the temp file at a specific path (sync)
    ///
    /// **Warning**: This WILL block the current thread.
    pub fn at_path_sync(self, path: impl AsRef<Path>) -> Result<SecureTempFile, Problem> {
        self.create_at_path(path.as_ref().to_path_buf())
    }

    // =========================================================================
    // Internal Implementation
    // =========================================================================

    fn build_sync_impl(self) -> Result<SecureTempFile, Problem> {
        let dir = self.dir.clone().unwrap_or_else(std::env::temp_dir);

        // Generate a unique filename
        let filename = format!("{}{}{}", self.prefix, generate_random_id(), self.suffix);
        let path = dir.join(filename);

        self.create_at_path(path)
    }

    fn create_at_path(self, path: PathBuf) -> Result<SecureTempFile, Problem> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent).map_err(|e| {
                Problem::io(format!(
                    "Failed to create parent directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        // Create file with secure permissions
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .read(true)
                .create_new(true) // Fail if exists - prevents race conditions
                .mode(self.mode.as_raw())
                .open(&path)
                .map_err(|e| Problem::io(format!("Failed to create temp file: {}", e)))?
        };

        #[cfg(not(unix))]
        let file = {
            OpenOptions::new()
                .write(true)
                .read(true)
                .create_new(true)
                .open(&path)
                .map_err(|e| Problem::io(format!("Failed to create temp file: {}", e)))?
        };

        observe::debug(
            "io.temp.create",
            format!(
                "Created secure temp file {} (mode={:o}, secure_delete={})",
                path.display(),
                self.mode.as_raw(),
                self.secure_delete
            ),
        );

        Ok(SecureTempFile {
            path,
            file: Some(file),
            secure_delete: self.secure_delete,
            deleted: false,
        })
    }
}

impl Default for SecureTempFileBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a random ID for temp file names
fn generate_random_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let random: u32 = rand::random();
    format!("{:x}{:08x}", timestamp % 0xFFFFFFFF, random)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use tempfile::tempdir;

    // =========================================================================
    // Async Tests
    // =========================================================================

    #[tokio::test]
    async fn test_secure_temp_file_async_basic() {
        let temp = SecureTempFile::new().await.expect("create temp file");
        assert!(temp.path().exists());

        let path = temp.path().to_path_buf();
        drop(temp);

        // Should be deleted after drop
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn test_secure_temp_file_async_builder() {
        let dir = tempdir().expect("create temp dir");

        let temp = SecureTempFile::builder()
            .prefix("test-")
            .suffix(".tmp")
            .in_dir(dir.path())
            .build()
            .await
            .expect("build temp file");

        let filename = temp
            .path()
            .file_name()
            .expect("has filename")
            .to_string_lossy();
        assert!(filename.starts_with("test-"));
        assert!(filename.ends_with(".tmp"));
    }

    #[tokio::test]
    async fn test_secure_temp_file_async_at_path() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("specific.env");

        let mut temp = SecureTempFile::at_path(&path)
            .await
            .expect("create at path");
        temp.write_all(b"VAR=value").expect("write");

        assert_eq!(temp.path(), path);
        assert!(path.exists());
    }

    #[tokio::test]
    async fn test_secure_temp_file_async_delete() {
        let mut temp = SecureTempFile::new().await.expect("create temp file");
        let path = temp.path().to_path_buf();

        temp.delete().await.expect("async delete");
        assert!(!path.exists());

        // Second delete should be no-op
        temp.delete().await.expect("second delete should succeed");
    }

    #[tokio::test]
    async fn test_secure_temp_file_async_secure_delete() {
        let dir = tempdir().expect("create temp dir");

        let mut temp = SecureTempFile::builder()
            .in_dir(dir.path())
            .secure_delete(true)
            .build()
            .await
            .expect("build with secure delete");

        temp.write_all(b"sensitive data").expect("write");
        temp.sync().expect("sync");

        let path = temp.path().to_path_buf();
        assert!(temp.secure_delete_enabled());

        temp.delete().await.expect("async secure delete");
        assert!(!path.exists());
    }

    // =========================================================================
    // Sync Tests
    // =========================================================================

    #[test]
    fn test_secure_temp_file_sync_basic() {
        let temp = SecureTempFile::new_sync().expect("create temp file");
        assert!(temp.path().exists());

        let path = temp.path().to_path_buf();
        drop(temp);

        // Should be deleted after drop
        assert!(!path.exists());
    }

    #[test]
    fn test_secure_temp_file_sync_write() {
        let mut temp = SecureTempFile::new_sync().expect("create temp file");
        temp.write_all(b"test data").expect("write data");
        temp.sync().expect("sync");

        let contents = fs::read_to_string(temp.path()).expect("read file");
        assert_eq!(contents, "test data");
    }

    #[test]
    fn test_secure_temp_file_sync_builder() {
        let dir = tempdir().expect("create temp dir");

        let temp = SecureTempFile::builder()
            .prefix("test-")
            .suffix(".tmp")
            .in_dir(dir.path())
            .build_sync()
            .expect("build temp file");

        let filename = temp
            .path()
            .file_name()
            .expect("has filename")
            .to_string_lossy();
        assert!(filename.starts_with("test-"));
        assert!(filename.ends_with(".tmp"));
    }

    #[test]
    fn test_secure_temp_file_sync_at_path() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("specific.env");

        let mut temp = SecureTempFile::at_path_sync(&path).expect("create at path");
        temp.write_all(b"VAR=value").expect("write");

        assert_eq!(temp.path(), path);
        assert!(path.exists());
    }

    #[test]
    fn test_secure_temp_file_sync_creates_parent_dirs() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("nested/dirs/file.tmp");

        let temp = SecureTempFile::at_path_sync(&path).expect("create with nested dirs");
        assert!(temp.path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_secure_temp_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = SecureTempFile::new_sync().expect("create temp file");
        let metadata = fs::metadata(temp.path()).expect("get metadata");
        let mode = metadata.permissions().mode() & 0o777;

        assert_eq!(mode, 0o600, "File should have 0600 permissions");
    }

    #[test]
    fn test_secure_temp_file_sync_secure_delete() {
        let dir = tempdir().expect("create temp dir");

        let mut temp = SecureTempFile::builder()
            .in_dir(dir.path())
            .secure_delete(true)
            .build_sync()
            .expect("build with secure delete");

        temp.write_all(b"sensitive data").expect("write");
        temp.sync().expect("sync");

        let path = temp.path().to_path_buf();
        assert!(temp.secure_delete_enabled());

        drop(temp);
        assert!(!path.exists());
    }

    #[test]
    fn test_secure_temp_file_sync_explicit_delete() {
        let mut temp = SecureTempFile::new_sync().expect("create temp file");
        let path = temp.path().to_path_buf();

        temp.delete_sync().expect("explicit delete");
        assert!(!path.exists());

        // Second delete should be no-op
        temp.delete_sync().expect("second delete should succeed");
    }

    #[test]
    fn test_secure_temp_file_sync_close_then_delete() {
        let mut temp = SecureTempFile::new_sync().expect("create temp file");
        let path = temp.path().to_path_buf();

        temp.write_all(b"data").expect("write");
        temp.close().expect("close");

        // File should still exist after close
        assert!(path.exists());

        // But be deleted on drop
        drop(temp);
        assert!(!path.exists());
    }

    #[test]
    fn test_secure_temp_file_write_trait() {
        use std::io::Write;

        let mut temp = SecureTempFile::new_sync().expect("create temp file");

        writeln!(temp, "line 1").expect("write line 1");
        writeln!(temp, "line 2").expect("write line 2");
        temp.flush().expect("flush");

        let contents = fs::read_to_string(temp.path()).expect("read");
        assert_eq!(contents, "line 1\nline 2\n");
    }
}
