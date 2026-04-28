//! Secure file deletion with compliance support
//!
//! Provides secure file deletion with multi-pass overwrite patterns
//! for compliance with various security standards.
//!
//! # Async-First Design
//!
//! This module follows the async-first design pattern. The primary API is async:
//!
//! ```ignore
//! use octarine::io::{SecureDelete, secure_delete, DeleteMethod};
//!
//! // Async (default) - recommended
//! secure_delete("/path/to/file").await?;
//!
//! // Or using the builder
//! SecureDelete::new("/path/to/file").await?
//!     .method(DeleteMethod::Dod522022M)
//!     .execute().await?;
//!
//! // Sync (explicit opt-in) - use builder with _sync methods
//! SecureDelete::new_sync("/path/to/file")?.execute_sync()?;
//! ```
//!
//! # Supported Standards
//!
//! - **NIST 800-88**: Single pass of zeros (sufficient for modern storage)
//! - **DoD 5220.22-M**: 3-pass pattern (0x00, 0xFF, random)
//! - **Gutmann**: 35-pass pattern (historical, rarely needed)
//!
//! # Security Notes
//!
//! - Modern SSDs and flash storage may not benefit from multi-pass overwrites
//!   due to wear leveling. NIST 800-88 recommends cryptographic erasure for SSDs.
//! - For maximum security, use full-disk encryption with key destruction.
//! - This implementation is suitable for compliance requirements on traditional
//!   storage and provides defense-in-depth for SSDs.

// Allow dead code - these are public APIs for library consumers
#![allow(dead_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::observe::{self, Problem};
use crate::primitives::runtime::r#async::spawn_blocking;

/// Secure file deletion method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeleteMethod {
    /// NIST 800-88 Clear: Single pass of zeros
    ///
    /// Recommended for most modern storage. Fast and sufficient for
    /// protection against software-based recovery attempts.
    #[default]
    Nist80088,

    /// DoD 5220.22-M: 3-pass overwrite
    ///
    /// Pattern: 0x00, 0xFF, random
    /// Suitable for compliance with DoD requirements.
    Dod522022M,

    /// Extended 7-pass overwrite
    ///
    /// Pattern: 0x00, 0xFF, random, 0x00, 0xFF, random, random
    /// Higher assurance for sensitive data.
    Extended7Pass,

    /// Quick deletion: random overwrite only
    ///
    /// Single pass of random data. Faster than multi-pass but
    /// still prevents casual recovery.
    Quick,
}

impl DeleteMethod {
    /// Get the number of overwrite passes for this method
    #[must_use]
    pub fn passes(&self) -> usize {
        match self {
            DeleteMethod::Nist80088 => 1,
            DeleteMethod::Dod522022M => 3,
            DeleteMethod::Extended7Pass => 7,
            DeleteMethod::Quick => 1,
        }
    }

    /// Get the name of the standard/method
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            DeleteMethod::Nist80088 => "NIST 800-88",
            DeleteMethod::Dod522022M => "DoD 5220.22-M",
            DeleteMethod::Extended7Pass => "7-Pass Extended",
            DeleteMethod::Quick => "Quick",
        }
    }
}

/// Secure file deletion with configurable overwrite patterns
///
/// # Examples
///
/// ```ignore
/// use octarine::io::{SecureDelete, DeleteMethod};
///
/// // Async (default)
/// SecureDelete::new("/path/to/secret.txt").await?.execute().await?;
///
/// // With verification and DoD compliance
/// let result = SecureDelete::new("/path/to/classified.doc").await?
///     .method(DeleteMethod::Dod522022M)
///     .verify(true)
///     .execute().await?;
///
/// println!("Deleted {} bytes in {} passes", result.bytes_overwritten, result.passes);
///
/// // Sync (explicit opt-in)
/// SecureDelete::new_sync("/path/to/secret.txt")?.execute_sync()?;
/// ```
pub struct SecureDelete {
    path: PathBuf,
    method: DeleteMethod,
    verify: bool,
}

/// Result of a secure deletion operation
#[derive(Debug, Clone)]
pub struct SecureDeleteResult {
    /// Path that was deleted
    pub path: PathBuf,
    /// Method used for deletion
    pub method: DeleteMethod,
    /// Number of overwrite passes performed
    pub passes: usize,
    /// Total bytes overwritten
    pub bytes_overwritten: u64,
    /// Whether verification was performed
    pub verified: bool,
}

impl SecureDelete {
    // =========================================================================
    // Async API (Default)
    // =========================================================================

    /// Create a new secure delete operation for the given path (async)
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file to delete
    ///
    /// # Errors
    ///
    /// Returns an error if the path doesn't exist or isn't a file.
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, Problem> {
        let path = path.as_ref().to_path_buf();
        spawn_blocking(move || Self::new_sync_impl(path))
            .await
            .map_err(|e| Problem::operation_failed(format!("Async operation failed: {}", e)))?
    }

    /// Execute the secure deletion (async)
    ///
    /// Performs the configured overwrite pattern, optionally verifies
    /// each pass, then deletes the file.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be opened for writing
    /// - Any overwrite pass fails
    /// - Verification fails (if enabled)
    /// - The file cannot be deleted
    pub async fn execute(self) -> Result<SecureDeleteResult, Problem> {
        spawn_blocking(move || self.execute_sync_impl())
            .await
            .map_err(|e| Problem::operation_failed(format!("Async operation failed: {}", e)))?
    }

    // =========================================================================
    // Sync API (Explicit Opt-In)
    // =========================================================================

    /// Create a new secure delete operation for the given path (sync)
    ///
    /// **Warning**: This WILL block the current thread.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file to delete
    ///
    /// # Errors
    ///
    /// Returns an error if the path doesn't exist or isn't a file.
    pub fn new_sync(path: impl AsRef<Path>) -> Result<Self, Problem> {
        Self::new_sync_impl(path.as_ref().to_path_buf())
    }

    /// Execute the secure deletion (sync)
    ///
    /// **Warning**: This WILL block the current thread.
    ///
    /// Performs the configured overwrite pattern, optionally verifies
    /// each pass, then deletes the file.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be opened for writing
    /// - Any overwrite pass fails
    /// - Verification fails (if enabled)
    /// - The file cannot be deleted
    pub fn execute_sync(self) -> Result<SecureDeleteResult, Problem> {
        self.execute_sync_impl()
    }

    // =========================================================================
    // Builder Methods (work with both async and sync)
    // =========================================================================

    /// Set the deletion method
    ///
    /// # Examples
    ///
    /// ```ignore
    /// SecureDelete::new(path).await?
    ///     .method(DeleteMethod::Dod522022M)
    ///     .execute().await?;
    /// ```
    #[must_use]
    pub fn method(mut self, method: DeleteMethod) -> Self {
        self.method = method;
        self
    }

    /// Enable or disable verification
    ///
    /// When enabled, reads back each pass to verify the overwrite
    /// was successful. This doubles the I/O but provides higher assurance.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// SecureDelete::new(path).await?
    ///     .verify(true)
    ///     .execute().await?;
    /// ```
    #[must_use]
    pub fn verify(mut self, verify: bool) -> Self {
        self.verify = verify;
        self
    }

    // =========================================================================
    // Internal Implementation
    // =========================================================================

    fn new_sync_impl(path: PathBuf) -> Result<Self, Problem> {
        if !path.exists() {
            return Err(Problem::io(format!(
                "File does not exist: {}",
                path.display()
            )));
        }

        if !path.is_file() {
            return Err(Problem::io(format!(
                "Path is not a file: {}",
                path.display()
            )));
        }

        Ok(Self {
            path,
            method: DeleteMethod::default(),
            verify: false,
        })
    }

    fn execute_sync_impl(self) -> Result<SecureDeleteResult, Problem> {
        let path_str = self.path.display().to_string();
        let metadata = fs::metadata(&self.path)
            .map_err(|e| Problem::io(format!("Failed to get file metadata: {}", e)))?;
        let file_size = metadata.len();

        observe::info(
            "io.delete.start",
            format!(
                "Starting secure deletion of {} ({} bytes, method={})",
                path_str,
                file_size,
                self.method.name()
            ),
        );

        // Perform overwrite passes
        if file_size > 0 {
            self.perform_overwrites(file_size)?;
        }

        // Delete the file
        fs::remove_file(&self.path)
            .map_err(|e| Problem::io(format!("Failed to delete file: {}", e)))?;

        let result = SecureDeleteResult {
            path: self.path.clone(),
            method: self.method,
            passes: self.method.passes(),
            bytes_overwritten: file_size,
            verified: self.verify,
        };

        observe::info(
            "io.delete.complete",
            format!(
                "Secure deletion complete: {} ({} bytes, {} passes, verified={})",
                path_str, file_size, result.passes, self.verify
            ),
        );

        Ok(result)
    }

    /// Perform the overwrite passes based on the selected method
    fn perform_overwrites(&self, file_size: u64) -> Result<(), Problem> {
        let passes = self.get_pass_patterns();
        let total_passes = passes.len();

        for (i, pattern) in passes.iter().enumerate() {
            // Safe: i is always < total_passes since we're iterating
            let pass_num = i.saturating_add(1);
            observe::debug(
                "io.delete.pass",
                format!(
                    "Pass {}/{}: {} on {}",
                    pass_num,
                    total_passes,
                    pattern.name(),
                    self.path.display()
                ),
            );

            self.overwrite_with_pattern(file_size, pattern)?;

            if self.verify {
                self.validate_overwrite(file_size, pattern)?;
            }
        }

        Ok(())
    }

    /// Get the patterns for each pass based on the deletion method
    fn get_pass_patterns(&self) -> Vec<OverwritePattern> {
        match self.method {
            DeleteMethod::Nist80088 => vec![OverwritePattern::Zeros],
            DeleteMethod::Dod522022M => vec![
                OverwritePattern::Zeros,
                OverwritePattern::Ones,
                OverwritePattern::Random,
            ],
            DeleteMethod::Extended7Pass => vec![
                OverwritePattern::Zeros,
                OverwritePattern::Ones,
                OverwritePattern::Random,
                OverwritePattern::Zeros,
                OverwritePattern::Ones,
                OverwritePattern::Random,
                OverwritePattern::Random,
            ],
            DeleteMethod::Quick => vec![OverwritePattern::Random],
        }
    }

    /// Overwrite the file with the specified pattern
    fn overwrite_with_pattern(
        &self,
        file_size: u64,
        pattern: &OverwritePattern,
    ) -> Result<(), Problem> {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(|e| Problem::io(format!("Failed to open file for overwrite: {}", e)))?;

        // Use 64KB buffer for efficiency
        const BUFFER_SIZE: usize = 64 * 1024;
        let mut buffer = vec![0u8; BUFFER_SIZE];
        let mut remaining = file_size;

        while remaining > 0 {
            let chunk_size = std::cmp::min(remaining as usize, BUFFER_SIZE);

            // Fill buffer with pattern - get_mut returns Option, but chunk_size <= BUFFER_SIZE
            if let Some(slice) = buffer.get_mut(..chunk_size) {
                pattern.fill(slice);
            }

            // Write the chunk - get returns Option, but chunk_size <= BUFFER_SIZE
            if let Some(slice) = buffer.get(..chunk_size) {
                file.write_all(slice).map_err(|e| {
                    Problem::io(format!("Failed to write overwrite pattern: {}", e))
                })?;
            }

            remaining = remaining.saturating_sub(chunk_size as u64);
        }

        file.sync_all()
            .map_err(|e| Problem::io(format!("Failed to sync after overwrite: {}", e)))?;

        Ok(())
    }

    /// Verify that the overwrite was successful
    fn validate_overwrite(
        &self,
        file_size: u64,
        pattern: &OverwritePattern,
    ) -> Result<(), Problem> {
        let mut file = File::open(&self.path)
            .map_err(|e| Problem::io(format!("Failed to open file for verification: {}", e)))?;

        file.seek(SeekFrom::Start(0))
            .map_err(|e| Problem::io(format!("Failed to seek for verification: {}", e)))?;

        const BUFFER_SIZE: usize = 64 * 1024;
        let mut buffer = vec![0u8; BUFFER_SIZE];
        let mut remaining = file_size;

        while remaining > 0 {
            let chunk_size = std::cmp::min(remaining as usize, BUFFER_SIZE);

            // Read into buffer - get_mut returns Option, but chunk_size <= BUFFER_SIZE
            let bytes_read = if let Some(slice) = buffer.get_mut(..chunk_size) {
                file.read(slice)
                    .map_err(|e| Problem::io(format!("Failed to read for verification: {}", e)))?
            } else {
                0
            };

            if bytes_read == 0 {
                break;
            }

            // Verify pattern (skip for random since we can't verify random data)
            if let Some(slice) = buffer.get(..bytes_read)
                && !matches!(pattern, OverwritePattern::Random)
                && !pattern.verify(slice)
            {
                return Err(Problem::io(format!(
                    "Verification failed: data does not match {} pattern",
                    pattern.name()
                )));
            }

            remaining = remaining.saturating_sub(bytes_read as u64);
        }

        observe::debug(
            "io.delete.verify",
            format!(
                "Verification passed for {} pattern on {}",
                pattern.name(),
                self.path.display()
            ),
        );

        Ok(())
    }
}

/// Overwrite pattern types
#[derive(Debug, Clone, Copy)]
enum OverwritePattern {
    Zeros,
    Ones,
    Random,
}

impl OverwritePattern {
    /// Get the name of this pattern
    fn name(&self) -> &'static str {
        match self {
            OverwritePattern::Zeros => "0x00",
            OverwritePattern::Ones => "0xFF",
            OverwritePattern::Random => "random",
        }
    }

    /// Fill a buffer with this pattern
    fn fill(&self, buffer: &mut [u8]) {
        match self {
            OverwritePattern::Zeros => buffer.fill(0x00),
            OverwritePattern::Ones => buffer.fill(0xFF),
            OverwritePattern::Random => {
                for byte in buffer.iter_mut() {
                    *byte = rand::random();
                }
            }
        }
    }

    /// Verify that a buffer matches this pattern
    fn verify(&self, buffer: &[u8]) -> bool {
        match self {
            OverwritePattern::Zeros => buffer.iter().all(|&b| b == 0x00),
            OverwritePattern::Ones => buffer.iter().all(|&b| b == 0xFF),
            OverwritePattern::Random => true, // Can't verify random
        }
    }
}

// =============================================================================
// Async Convenience Functions (Default)
// =============================================================================

/// Convenience function for quick secure deletion (async)
///
/// Uses the default NIST 800-88 method without verification.
///
/// # Examples
///
/// ```ignore
/// use octarine::io::secure_delete;
///
/// secure_delete("/path/to/file").await?;
/// ```
pub async fn secure_delete(path: impl AsRef<Path>) -> Result<SecureDeleteResult, Problem> {
    SecureDelete::new(path).await?.execute().await
}

/// Convenience function for DoD-compliant secure deletion (async)
///
/// Uses DoD 5220.22-M method with verification.
///
/// # Examples
///
/// ```ignore
/// use octarine::io::secure_delete_dod;
///
/// secure_delete_dod("/path/to/classified").await?;
/// ```
pub async fn secure_delete_dod(path: impl AsRef<Path>) -> Result<SecureDeleteResult, Problem> {
    SecureDelete::new(path)
        .await?
        .method(DeleteMethod::Dod522022M)
        .verify(true)
        .execute()
        .await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn create_test_file(path: &Path, content: &[u8]) {
        let mut file = File::create(path).expect("create test file");
        file.write_all(content).expect("write content");
        file.sync_all().expect("sync");
    }

    // =========================================================================
    // Async Tests
    // =========================================================================

    #[tokio::test]
    async fn test_secure_delete_async_basic() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");

        create_test_file(&path, b"sensitive data here");
        assert!(path.exists());

        let result = SecureDelete::new(&path)
            .await
            .expect("create secure delete")
            .execute()
            .await
            .expect("execute delete");

        assert!(!path.exists());
        assert_eq!(result.method, DeleteMethod::Nist80088);
        assert_eq!(result.passes, 1);
    }

    #[tokio::test]
    async fn test_secure_delete_async_dod() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("classified.doc");

        create_test_file(&path, b"classified content");

        let result = SecureDelete::new(&path)
            .await
            .expect("create secure delete")
            .method(DeleteMethod::Dod522022M)
            .execute()
            .await
            .expect("execute delete");

        assert!(!path.exists());
        assert_eq!(result.method, DeleteMethod::Dod522022M);
        assert_eq!(result.passes, 3);
    }

    #[tokio::test]
    async fn test_secure_delete_async_convenience() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("convenience.txt");

        create_test_file(&path, b"convenience test");

        secure_delete(&path).await.expect("secure delete");
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn test_secure_delete_async_dod_convenience() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("dod.txt");

        create_test_file(&path, b"dod compliance test");

        let result = secure_delete_dod(&path).await.expect("dod delete");
        assert!(!path.exists());
        assert_eq!(result.method, DeleteMethod::Dod522022M);
        assert!(result.verified);
    }

    /// Async path against a missing file: must return an error with the
    /// "does not exist" wording, leave no residue, and not panic. Mirrors
    /// the existing sync test (`test_secure_delete_sync_nonexistent`)
    /// but exercises the `secure_delete()` async entry point.
    #[tokio::test]
    async fn test_secure_delete_async_nonexistent() {
        let dir = tempdir().expect("create temp dir");
        let missing = dir.path().join("does_not_exist.txt");
        // Sanity: the file must really not exist for this test to mean anything.
        assert!(
            !missing.exists(),
            "test fixture must not pre-create the file"
        );

        let result = secure_delete(&missing).await;
        let err = result.expect_err("missing file must produce an error");

        let message = err.to_string();
        assert!(
            message.contains("does not exist"),
            "error should mention 'does not exist', got: {message}",
        );

        // No residue: the parent dir is untouched and no file was created
        // at the rejected path.
        assert!(dir.path().exists(), "parent tempdir must still exist");
        assert!(
            !missing.exists(),
            "must not create the file we tried to delete"
        );
    }

    /// Async path against a directory: must reject with the "not a file"
    /// wording. Mirrors `test_secure_delete_sync_directory` for the async
    /// API.
    #[tokio::test]
    async fn test_secure_delete_async_directory() {
        let dir = tempdir().expect("create temp dir");

        let result = secure_delete(dir.path()).await;
        let err = result.expect_err("directory path must produce an error");

        let message = err.to_string();
        assert!(
            message.contains("not a file"),
            "error should mention 'not a file', got: {message}",
        );

        // Directory must remain — secure_delete must reject before touching it.
        assert!(dir.path().exists(), "directory must remain after rejection");
        assert!(
            dir.path().is_dir(),
            "directory entry must still be a directory"
        );
    }

    // =========================================================================
    // Sync Tests
    // =========================================================================

    #[test]
    fn test_secure_delete_sync_basic() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");

        create_test_file(&path, b"sensitive data here");
        assert!(path.exists());

        let result = SecureDelete::new_sync(&path)
            .expect("create secure delete")
            .execute_sync()
            .expect("execute delete");

        assert!(!path.exists());
        assert_eq!(result.method, DeleteMethod::Nist80088);
        assert_eq!(result.passes, 1);
    }

    #[test]
    fn test_secure_delete_sync_dod() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("classified.doc");

        create_test_file(&path, b"classified content");

        let result = SecureDelete::new_sync(&path)
            .expect("create secure delete")
            .method(DeleteMethod::Dod522022M)
            .execute_sync()
            .expect("execute delete");

        assert!(!path.exists());
        assert_eq!(result.method, DeleteMethod::Dod522022M);
        assert_eq!(result.passes, 3);
    }

    #[test]
    fn test_secure_delete_sync_with_verification() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("verified.txt");

        create_test_file(&path, b"verify this deletion");

        let result = SecureDelete::new_sync(&path)
            .expect("create secure delete")
            .verify(true)
            .execute_sync()
            .expect("execute delete");

        assert!(!path.exists());
        assert!(result.verified);
    }

    #[test]
    fn test_secure_delete_sync_extended() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("extended.txt");

        create_test_file(&path, b"high security content");

        let result = SecureDelete::new_sync(&path)
            .expect("create secure delete")
            .method(DeleteMethod::Extended7Pass)
            .execute_sync()
            .expect("execute delete");

        assert!(!path.exists());
        assert_eq!(result.passes, 7);
    }

    #[test]
    fn test_secure_delete_sync_quick() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("quick.txt");

        create_test_file(&path, b"quick delete");

        let result = SecureDelete::new_sync(&path)
            .expect("create secure delete")
            .method(DeleteMethod::Quick)
            .execute_sync()
            .expect("execute delete");

        assert!(!path.exists());
        assert_eq!(result.passes, 1);
    }

    #[test]
    fn test_secure_delete_sync_empty_file() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("empty.txt");

        create_test_file(&path, b"");

        let result = SecureDelete::new_sync(&path)
            .expect("create secure delete")
            .execute_sync()
            .expect("execute delete");

        assert!(!path.exists());
        assert_eq!(result.bytes_overwritten, 0);
    }

    #[test]
    fn test_secure_delete_sync_large_file() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("large.bin");

        // Create a file larger than buffer size
        let content = vec![0xABu8; 128 * 1024]; // 128KB
        create_test_file(&path, &content);

        let result = SecureDelete::new_sync(&path)
            .expect("create secure delete")
            .method(DeleteMethod::Dod522022M)
            .execute_sync()
            .expect("execute delete");

        assert!(!path.exists());
        assert_eq!(result.bytes_overwritten, 128 * 1024);
    }

    #[test]
    fn test_secure_delete_sync_nonexistent() {
        let result = SecureDelete::new_sync("/nonexistent/path/file.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_delete_sync_directory() {
        let dir = tempdir().expect("create temp dir");
        let result = SecureDelete::new_sync(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_method_info() {
        assert_eq!(DeleteMethod::Nist80088.passes(), 1);
        assert_eq!(DeleteMethod::Nist80088.name(), "NIST 800-88");

        assert_eq!(DeleteMethod::Dod522022M.passes(), 3);
        assert_eq!(DeleteMethod::Dod522022M.name(), "DoD 5220.22-M");

        assert_eq!(DeleteMethod::Extended7Pass.passes(), 7);
        assert_eq!(DeleteMethod::Quick.passes(), 1);
    }
}
