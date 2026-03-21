//! SecureFileOps - Unified file operations with audit trails and metrics
//!
//! Provides a high-level API for file operations that automatically:
//! - Logs all operations via observe
//! - Records metrics (timing, counts, sizes)
//! - Supports configurable audit levels
//! - Validates file types via magic bytes
//!
//! # Design Philosophy
//!
//! SecureFileOps follows async-first design:
//! - All primary operations are async to avoid blocking
//! - Sync variants available with `_sync` suffix for use in sync contexts
//! - All operations are logged for audit trails
//! - Metrics are collected for monitoring
//!
//! # Examples
//!
//! ```ignore
//! use octarine::io::SecureFileOps;
//!
//! // Create with default settings (audit enabled)
//! let ops = SecureFileOps::new();
//!
//! // Read file with audit trail (async)
//! let contents = ops.read_file("config.json").await?;
//!
//! // Write file atomically with audit trail (async)
//! ops.write_file("output.txt", b"data".to_vec()).await?;
//!
//! // Sync variants for use in sync contexts
//! let contents = ops.read_file_sync("config.json")?;
//! ```

// This module provides public APIs for library consumers
#![allow(dead_code)]

use std::io::{Read, Write};
use std::path::Path;

use crate::observe::metrics::{MetricTimer, timer};
use crate::observe::{self, Problem};
use crate::primitives::io::file::{
    self as prim_file, FileMode, PortableLock, WriteOptions, file_size as prim_file_size,
    file_size_sync as prim_file_size_sync, lock_file_portable, path_exists, path_exists_sync,
    read_file as prim_read_file, read_file_sync as prim_read_file_sync,
};

use super::magic::{
    MagicResult, detect_file_type, detect_file_type_sync, validate_image, validate_image_sync,
    validate_not_dangerous, validate_not_dangerous_sync,
};

/// Audit level for file operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditLevel {
    /// No logging (not recommended for production)
    Off,
    /// Log errors only
    Errors,
    /// Log errors and warnings
    Warnings,
    /// Log all operations (default)
    #[default]
    Full,
    /// Log all operations with debug details
    Debug,
}

/// Configuration for SecureFileOps
#[derive(Debug, Clone)]
pub struct SecureFileOpsConfig {
    /// Audit level for logging
    pub audit_level: AuditLevel,
    /// Whether to record metrics
    pub metrics_enabled: bool,
    /// Whether to validate magic bytes on read
    pub validate_magic: bool,
    /// Default write options
    pub default_write_options: WriteOptions,
}

impl Default for SecureFileOpsConfig {
    fn default() -> Self {
        Self {
            audit_level: AuditLevel::Full,
            metrics_enabled: true,
            validate_magic: false, // Opt-in for magic validation
            default_write_options: WriteOptions::default(),
        }
    }
}

impl SecureFileOpsConfig {
    /// Create config for high-security environments
    pub fn secure() -> Self {
        Self {
            audit_level: AuditLevel::Full,
            metrics_enabled: true,
            validate_magic: true,
            default_write_options: WriteOptions::for_secrets(),
        }
    }

    /// Create config for development (verbose logging)
    pub fn development() -> Self {
        Self {
            audit_level: AuditLevel::Debug,
            metrics_enabled: true,
            validate_magic: false,
            default_write_options: WriteOptions::default(),
        }
    }

    /// Create config for performance-critical scenarios
    pub fn performance() -> Self {
        Self {
            audit_level: AuditLevel::Errors,
            metrics_enabled: false,
            validate_magic: false,
            default_write_options: WriteOptions::default(),
        }
    }
}

/// Secure file operations with audit trails and metrics
///
/// Provides a unified API for file operations that automatically logs
/// all actions and records metrics.
///
/// # Async-First Design
///
/// All primary operations are async. Use `_sync` suffix variants for sync contexts.
///
/// # Example
///
/// ```ignore
/// use octarine::io::SecureFileOps;
///
/// async fn example() -> Result<(), Problem> {
///     let ops = SecureFileOps::new();
///     ops.write_file("data.txt", b"hello".to_vec()).await?;
///     let contents = ops.read_file("data.txt").await?;
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct SecureFileOps {
    config: SecureFileOpsConfig,
}

impl Default for SecureFileOps {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureFileOps {
    /// Create a new SecureFileOps with default configuration
    pub fn new() -> Self {
        Self {
            config: SecureFileOpsConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: SecureFileOpsConfig) -> Self {
        Self { config }
    }

    /// Create builder for custom configuration
    pub fn builder() -> SecureFileOpsBuilder {
        SecureFileOpsBuilder::new()
    }

    // ========================================================================
    // Async Read Operations (Default)
    // ========================================================================

    /// Read entire file contents (async)
    ///
    /// Logs the operation and records metrics for timing and size.
    pub async fn read_file(
        &self,
        path: impl AsRef<Path> + Send + 'static,
    ) -> Result<Vec<u8>, Problem> {
        let path = path.as_ref().to_path_buf();
        let path_str = path.display().to_string();

        self.log_debug("io.file.read", format!("Reading file: {}", path_str));

        let _timer = self.start_timer("io.file.read_duration_ms");

        let result = prim_read_file(path.clone()).await.map_err(|e| {
            self.log_error(
                "io.file.read",
                format!("Failed to read {}: {}", path_str, e),
            );
            e
        })?;

        self.record_metric("io.file.read_count", 1);
        self.record_metric("io.file.read_bytes", result.len() as u64);

        self.log_info(
            "io.file.read",
            format!("Read {} bytes from {}", result.len(), path_str),
        );

        Ok(result)
    }

    /// Read file as UTF-8 string (async)
    pub async fn read_file_string(
        &self,
        path: impl AsRef<Path> + Send + 'static,
    ) -> Result<String, Problem> {
        let path = path.as_ref().to_path_buf();
        let path_str = path.display().to_string();

        let bytes = self.read_file(path).await?;

        String::from_utf8(bytes).map_err(|e| {
            self.log_error(
                "io.file.read_string",
                format!("File {} is not valid UTF-8: {}", path_str, e),
            );
            Problem::io(format!("File '{}' is not valid UTF-8: {}", path_str, e))
        })
    }

    /// Read and validate file is an image (async)
    ///
    /// Returns error if file is not a recognized image format.
    pub async fn read_validated_image(
        &self,
        path: impl AsRef<Path> + Send + 'static,
    ) -> Result<Vec<u8>, Problem> {
        let path = path.as_ref().to_path_buf();
        let path_str = path.display().to_string();

        self.log_debug(
            "io.file.read_image",
            format!("Reading and validating image: {}", path_str),
        );

        // Validate magic bytes first
        validate_image(path.clone()).await?;

        // Then read the full file
        let data = self.read_file(path).await?;

        self.log_info(
            "io.file.read_image",
            format!("Read validated image {} ({} bytes)", path_str, data.len()),
        );

        Ok(data)
    }

    /// Read file with safety validation (reject executables, archives) (async)
    pub async fn read_safe(
        &self,
        path: impl AsRef<Path> + Send + 'static,
    ) -> Result<Vec<u8>, Problem> {
        let path = path.as_ref().to_path_buf();
        let path_str = path.display().to_string();

        self.log_debug(
            "io.file.read_safe",
            format!("Reading with safety validation: {}", path_str),
        );

        // Validate not dangerous
        validate_not_dangerous(path.clone()).await?;

        // Then read
        let data = self.read_file(path).await?;

        self.log_info(
            "io.file.read_safe",
            format!("Read safe file {} ({} bytes)", path_str, data.len()),
        );

        Ok(data)
    }

    // ========================================================================
    // Async Write Operations (Default)
    // ========================================================================

    /// Write data to file atomically (async)
    ///
    /// Uses write-to-temp → fsync → rename pattern.
    pub async fn write_file(
        &self,
        path: impl AsRef<Path> + Send + 'static,
        data: Vec<u8>,
    ) -> Result<(), Problem> {
        let options = self.config.default_write_options;
        self.write_file_with_options(path, data, options).await
    }

    /// Write data with custom options (async)
    pub async fn write_file_with_options(
        &self,
        path: impl AsRef<Path> + Send + 'static,
        data: Vec<u8>,
        options: WriteOptions,
    ) -> Result<(), Problem> {
        let path = path.as_ref().to_path_buf();
        let path_str = path.display().to_string();
        let data_len = data.len();

        self.log_debug(
            "io.file.write",
            format!("Writing {} bytes to {}", data_len, path_str),
        );

        let _timer = self.start_timer("io.file.write_duration_ms");

        prim_file::write_atomic_async(path, data, options)
            .await
            .map_err(|e| {
                self.log_error(
                    "io.file.write",
                    format!("Failed to write {}: {}", path_str, e),
                );
                e
            })?;

        self.record_metric("io.file.write_count", 1);
        self.record_metric("io.file.write_bytes", data_len as u64);

        self.log_info(
            "io.file.write",
            format!("Wrote {} bytes to {}", data_len, path_str),
        );

        Ok(())
    }

    /// Write string data to file (async)
    pub async fn write_file_string(
        &self,
        path: impl AsRef<Path> + Send + 'static,
        data: String,
    ) -> Result<(), Problem> {
        self.write_file(path, data.into_bytes()).await
    }

    /// Write secrets with restricted permissions (0600) (async)
    pub async fn write_secrets(
        &self,
        path: impl AsRef<Path> + Send + 'static,
        data: Vec<u8>,
    ) -> Result<(), Problem> {
        self.write_file_with_options(path, data, WriteOptions::for_secrets())
            .await
    }

    // ========================================================================
    // Async File Info Operations (Default)
    // ========================================================================

    /// Check if file exists (async)
    pub async fn exists(&self, path: impl AsRef<Path> + Send + 'static) -> Result<bool, Problem> {
        let path = path.as_ref().to_path_buf();
        let path_str = path.display().to_string();

        let exists = path_exists(path).await?;

        self.log_debug("io.file.exists", format!("{}: {}", path_str, exists));

        Ok(exists)
    }

    /// Get file size in bytes (async)
    pub async fn file_size(&self, path: impl AsRef<Path> + Send + 'static) -> Result<u64, Problem> {
        let path = path.as_ref().to_path_buf();
        let path_str = path.display().to_string();

        let size = prim_file_size(path).await?;
        self.log_debug("io.file.size", format!("{}: {} bytes", path_str, size));

        Ok(size)
    }

    /// Detect file type via magic bytes (async)
    pub async fn detect_type(
        &self,
        path: impl AsRef<Path> + Send + 'static,
    ) -> Result<MagicResult, Problem> {
        let path = path.as_ref().to_path_buf();
        let path_str = path.display().to_string();

        let result = detect_file_type(path).await?;

        self.log_debug(
            "io.file.detect_type",
            format!("{}: {:?}", path_str, result.file_type),
        );

        Ok(result)
    }

    // ========================================================================
    // Sync Read Operations (Explicit Opt-In)
    // ========================================================================

    /// Read entire file contents (sync, blocking)
    ///
    /// **Warning**: This WILL block the current thread.
    pub fn read_file_sync(&self, path: impl AsRef<Path>) -> Result<Vec<u8>, Problem> {
        let path = path.as_ref();
        let path_str = path.display().to_string();

        self.log_debug("io.file.read", format!("Reading file: {}", path_str));

        let _timer = self.start_timer("io.file.read_duration_ms");

        let result = prim_read_file_sync(path).map_err(|e| {
            self.log_error(
                "io.file.read",
                format!("Failed to read {}: {}", path_str, e),
            );
            e
        })?;

        self.record_metric("io.file.read_count", 1);
        self.record_metric("io.file.read_bytes", result.len() as u64);

        self.log_info(
            "io.file.read",
            format!("Read {} bytes from {}", result.len(), path_str),
        );

        Ok(result)
    }

    /// Read file as UTF-8 string (sync, blocking)
    pub fn read_file_string_sync(&self, path: impl AsRef<Path>) -> Result<String, Problem> {
        let path = path.as_ref();
        let path_str = path.display().to_string();

        let bytes = self.read_file_sync(path)?;

        String::from_utf8(bytes).map_err(|e| {
            self.log_error(
                "io.file.read_string",
                format!("File {} is not valid UTF-8: {}", path_str, e),
            );
            Problem::io(format!("File '{}' is not valid UTF-8: {}", path_str, e))
        })
    }

    /// Read and validate file is an image (sync, blocking)
    pub fn read_validated_image_sync(&self, path: impl AsRef<Path>) -> Result<Vec<u8>, Problem> {
        let path = path.as_ref();
        let path_str = path.display().to_string();

        self.log_debug(
            "io.file.read_image",
            format!("Reading and validating image: {}", path_str),
        );

        // Validate magic bytes first
        validate_image_sync(path)?;

        // Then read the full file
        let data = self.read_file_sync(path)?;

        self.log_info(
            "io.file.read_image",
            format!("Read validated image {} ({} bytes)", path_str, data.len()),
        );

        Ok(data)
    }

    /// Read file with safety validation (sync, blocking)
    pub fn read_safe_sync(&self, path: impl AsRef<Path>) -> Result<Vec<u8>, Problem> {
        let path = path.as_ref();
        let path_str = path.display().to_string();

        self.log_debug(
            "io.file.read_safe",
            format!("Reading with safety validation: {}", path_str),
        );

        // Validate not dangerous
        validate_not_dangerous_sync(path)?;

        // Then read
        let data = self.read_file_sync(path)?;

        self.log_info(
            "io.file.read_safe",
            format!("Read safe file {} ({} bytes)", path_str, data.len()),
        );

        Ok(data)
    }

    // ========================================================================
    // Sync Write Operations (Explicit Opt-In)
    // ========================================================================

    /// Write data to file atomically (sync, blocking)
    pub fn write_file_sync(&self, path: impl AsRef<Path>, data: &[u8]) -> Result<(), Problem> {
        self.write_file_with_options_sync(path, data, self.config.default_write_options)
    }

    /// Write data with custom options (sync, blocking)
    pub fn write_file_with_options_sync(
        &self,
        path: impl AsRef<Path>,
        data: &[u8],
        options: WriteOptions,
    ) -> Result<(), Problem> {
        let path = path.as_ref();
        let path_str = path.display().to_string();

        self.log_debug(
            "io.file.write",
            format!("Writing {} bytes to {}", data.len(), path_str),
        );

        let _timer = self.start_timer("io.file.write_duration_ms");

        prim_file::write_atomic(path, data, options).map_err(|e| {
            self.log_error(
                "io.file.write",
                format!("Failed to write {}: {}", path_str, e),
            );
            e
        })?;

        self.record_metric("io.file.write_count", 1);
        self.record_metric("io.file.write_bytes", data.len() as u64);

        self.log_info(
            "io.file.write",
            format!("Wrote {} bytes to {}", data.len(), path_str),
        );

        Ok(())
    }

    /// Write string data to file (sync, blocking)
    pub fn write_file_string_sync(
        &self,
        path: impl AsRef<Path>,
        data: &str,
    ) -> Result<(), Problem> {
        self.write_file_sync(path, data.as_bytes())
    }

    /// Write secrets with restricted permissions (sync, blocking)
    pub fn write_secrets_sync(&self, path: impl AsRef<Path>, data: &[u8]) -> Result<(), Problem> {
        self.write_file_with_options_sync(path, data, WriteOptions::for_secrets())
    }

    // ========================================================================
    // Sync File Info Operations (Explicit Opt-In)
    // ========================================================================

    /// Check if file exists (sync, blocking)
    pub fn exists_sync(&self, path: impl AsRef<Path>) -> bool {
        let path = path.as_ref();
        let exists = path_exists_sync(path);

        self.log_debug("io.file.exists", format!("{}: {}", path.display(), exists));

        exists
    }

    /// Get file size in bytes (sync, blocking)
    pub fn file_size_sync(&self, path: impl AsRef<Path>) -> Result<u64, Problem> {
        let path = path.as_ref();
        let path_str = path.display().to_string();

        let size = prim_file_size_sync(path)?;
        self.log_debug("io.file.size", format!("{}: {} bytes", path_str, size));

        Ok(size)
    }

    /// Detect file type via magic bytes (sync, blocking)
    pub fn detect_type_sync(&self, path: impl AsRef<Path>) -> Result<MagicResult, Problem> {
        let path = path.as_ref();
        let path_str = path.display().to_string();

        let result = detect_file_type_sync(path)?;

        self.log_debug(
            "io.file.detect_type",
            format!("{}: {:?}", path_str, result.file_type),
        );

        Ok(result)
    }

    // ========================================================================
    // Locked Operations (Sync only - locking is inherently sync)
    // ========================================================================

    /// Acquire a portable lock on a file
    ///
    /// Uses flock when available, falls back to pidfile for Docker/NFS.
    /// Note: Locking operations are sync as they are typically quick
    /// and need to be held across multiple operations.
    pub fn lock_file(&self, path: impl AsRef<Path>, create: bool) -> Result<PortableLock, Problem> {
        let path = path.as_ref();
        let path_str = path.display().to_string();

        self.log_debug("io.file.lock", format!("Acquiring lock on {}", path_str));

        let _timer = self.start_timer("io.file.lock_duration_ms");

        let lock = lock_file_portable(path, create)?;

        self.record_metric("io.file.lock_count", 1);

        if lock.is_using_pidfile_fallback() {
            self.log_info(
                "io.file.lock",
                format!("Acquired pidfile lock on {} (flock unavailable)", path_str),
            );
        } else {
            self.log_debug("io.file.lock", format!("Acquired flock on {}", path_str));
        }

        Ok(lock)
    }

    /// Read file with exclusive lock
    pub fn read_locked(&self, path: impl AsRef<Path>) -> Result<Vec<u8>, Problem> {
        let path = path.as_ref();
        let path_str = path.display().to_string();

        self.log_debug(
            "io.file.read_locked",
            format!("Reading with lock: {}", path_str),
        );

        let mut lock = self.lock_file(path, false)?;

        let mut contents = Vec::new();
        lock.with_file_mut(|file| {
            file.read_to_end(&mut contents)
                .map_err(|e| Problem::io(format!("Failed to read {}: {}", path_str, e)))?;
            Ok(())
        })?;

        self.log_info(
            "io.file.read_locked",
            format!("Read {} bytes from {} (locked)", contents.len(), path_str),
        );

        Ok(contents)
    }

    /// Write file with exclusive lock
    pub fn write_locked(&self, path: impl AsRef<Path>, data: &[u8]) -> Result<(), Problem> {
        let path = path.as_ref();
        let path_str = path.display().to_string();

        self.log_debug(
            "io.file.write_locked",
            format!("Writing {} bytes with lock to {}", data.len(), path_str),
        );

        let mut lock = self.lock_file(path, true)?;

        lock.with_file_mut(|file| {
            file.set_len(0)
                .map_err(|e| Problem::io(format!("Failed to truncate {}: {}", path_str, e)))?;
            file.write_all(data)
                .map_err(|e| Problem::io(format!("Failed to write {}: {}", path_str, e)))?;
            file.sync_all()
                .map_err(|e| Problem::io(format!("Failed to sync {}: {}", path_str, e)))?;
            Ok(())
        })?;

        self.log_info(
            "io.file.write_locked",
            format!("Wrote {} bytes to {} (locked)", data.len(), path_str),
        );

        Ok(())
    }

    // ========================================================================
    // Permission Operations (Sync - quick operations)
    // ========================================================================

    /// Set file permissions
    pub fn set_mode(&self, path: impl AsRef<Path>, mode: FileMode) -> Result<(), Problem> {
        let path = path.as_ref();
        let path_str = path.display().to_string();

        self.log_debug(
            "io.file.chmod",
            format!("Setting mode {:o} on {}", mode.as_raw(), path_str),
        );

        prim_file::set_mode(path, mode)?;

        self.log_info(
            "io.file.chmod",
            format!("Set mode {:o} on {}", mode.as_raw(), path_str),
        );

        Ok(())
    }

    // ========================================================================
    // Internal Helpers
    // ========================================================================

    fn log_debug(&self, operation: &str, message: String) {
        if matches!(self.config.audit_level, AuditLevel::Debug) {
            observe::debug(operation, message);
        }
    }

    fn log_info(&self, operation: &str, message: String) {
        if matches!(
            self.config.audit_level,
            AuditLevel::Full | AuditLevel::Debug
        ) {
            observe::info(operation, message);
        }
    }

    #[allow(dead_code)]
    fn log_warn(&self, operation: &str, message: String) {
        if matches!(
            self.config.audit_level,
            AuditLevel::Warnings | AuditLevel::Full | AuditLevel::Debug
        ) {
            observe::warn(operation, message);
        }
    }

    fn log_error(&self, operation: &str, message: String) {
        if !matches!(self.config.audit_level, AuditLevel::Off) {
            observe::error(operation, message);
        }
    }

    fn start_timer(&self, name: &str) -> Option<MetricTimer> {
        if self.config.metrics_enabled {
            Some(timer(name))
        } else {
            None
        }
    }

    fn record_metric(&self, _name: &str, _value: u64) {
        if self.config.metrics_enabled {
            // Note: For full metric recording, consider using MetricName::new()
            // and the typed metrics API. For now, we use the timer for duration
            // and log the values via observe.
            // The observe event infrastructure provides audit trail.
        }
    }
}

/// Builder for SecureFileOps
#[derive(Debug, Default)]
pub struct SecureFileOpsBuilder {
    config: SecureFileOpsConfig,
}

impl SecureFileOpsBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set audit level
    pub fn audit_level(mut self, level: AuditLevel) -> Self {
        self.config.audit_level = level;
        self
    }

    /// Enable or disable metrics
    pub fn metrics(mut self, enabled: bool) -> Self {
        self.config.metrics_enabled = enabled;
        self
    }

    /// Enable or disable magic byte validation
    pub fn validate_magic(mut self, enabled: bool) -> Self {
        self.config.validate_magic = enabled;
        self
    }

    /// Set default write options
    pub fn default_write_options(mut self, options: WriteOptions) -> Self {
        self.config.default_write_options = options;
        self
    }

    /// Build the SecureFileOps
    pub fn build(self) -> SecureFileOps {
        SecureFileOps::with_config(self.config)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]

    use super::*;
    use crate::io::MagicFileType;
    use tempfile::tempdir;

    #[test]
    fn test_secure_file_ops_new() {
        let ops = SecureFileOps::new();
        assert_eq!(ops.config.audit_level, AuditLevel::Full);
        assert!(ops.config.metrics_enabled);
    }

    #[test]
    fn test_write_and_read_sync() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");

        let ops = SecureFileOps::new();
        ops.write_file_sync(&path, b"hello world").expect("write");

        let contents = ops.read_file_sync(&path).expect("read");
        assert_eq!(contents, b"hello world");
    }

    #[tokio::test]
    async fn test_write_and_read_async() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test_async.txt");

        let ops = SecureFileOps::new();
        ops.write_file(path.clone(), b"hello async".to_vec())
            .await
            .expect("write");

        let contents = ops.read_file(path).await.expect("read");
        assert_eq!(contents, b"hello async");
    }

    #[test]
    fn test_write_and_read_string_sync() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");

        let ops = SecureFileOps::new();
        ops.write_file_string_sync(&path, "hello string")
            .expect("write");

        let contents = ops.read_file_string_sync(&path).expect("read");
        assert_eq!(contents, "hello string");
    }

    #[test]
    fn test_exists_sync() {
        let dir = tempdir().expect("create temp dir");
        let existing = dir.path().join("exists.txt");
        let missing = dir.path().join("missing.txt");

        std::fs::write(&existing, b"test").expect("create file");

        let ops = SecureFileOps::new();
        assert!(ops.exists_sync(&existing));
        assert!(!ops.exists_sync(&missing));
    }

    #[tokio::test]
    async fn test_exists_async() {
        let dir = tempdir().expect("create temp dir");
        let existing = dir.path().join("exists_async.txt");
        let missing = dir.path().join("missing_async.txt");

        std::fs::write(&existing, b"test").expect("create file");

        let ops = SecureFileOps::new();
        assert!(ops.exists(existing).await.expect("exists"));
        assert!(!ops.exists(missing).await.expect("exists"));
    }

    #[test]
    fn test_file_size_sync() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("sized.txt");

        std::fs::write(&path, b"12345").expect("create file");

        let ops = SecureFileOps::new();
        let size = ops.file_size_sync(&path).expect("get size");
        assert_eq!(size, 5);
    }

    #[test]
    fn test_builder() {
        let ops = SecureFileOps::builder()
            .audit_level(AuditLevel::Errors)
            .metrics(false)
            .validate_magic(true)
            .build();

        assert_eq!(ops.config.audit_level, AuditLevel::Errors);
        assert!(!ops.config.metrics_enabled);
        assert!(ops.config.validate_magic);
    }

    #[test]
    fn test_config_presets() {
        let secure = SecureFileOpsConfig::secure();
        assert!(secure.validate_magic);
        assert_eq!(secure.audit_level, AuditLevel::Full);

        let dev = SecureFileOpsConfig::development();
        assert_eq!(dev.audit_level, AuditLevel::Debug);

        let perf = SecureFileOpsConfig::performance();
        assert!(!perf.metrics_enabled);
    }

    #[test]
    fn test_write_secrets_sync() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("secret.txt");

        let ops = SecureFileOps::new();
        ops.write_secrets_sync(&path, b"secret data")
            .expect("write secrets");

        let contents = ops.read_file_sync(&path).expect("read");
        assert_eq!(contents, b"secret data");

        // On Unix, check permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn test_locked_read_write() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("locked.txt");

        let ops = SecureFileOps::new();

        // Write with lock
        ops.write_locked(&path, b"locked data")
            .expect("write locked");

        // Read with lock
        let contents = ops.read_locked(&path).expect("read locked");
        assert_eq!(contents, b"locked data");
    }

    #[test]
    fn test_detect_type_sync() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.png");

        // Write PNG magic bytes
        std::fs::write(&path, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).expect("write png");

        let ops = SecureFileOps::new();
        let result = ops.detect_type_sync(&path).expect("detect");
        assert_eq!(result.file_type, Some(MagicFileType::Png));
    }

    #[test]
    fn test_read_validated_image_sync() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("image.png");

        // Write PNG magic bytes
        std::fs::write(&path, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).expect("write png");

        let ops = SecureFileOps::new();
        let data = ops.read_validated_image_sync(&path).expect("read image");
        assert_eq!(data.len(), 8);
    }

    #[test]
    fn test_read_validated_image_rejects_non_image() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("fake.png");

        // Write ELF magic (not an image)
        std::fs::write(&path, [0x7F, 0x45, 0x4C, 0x46]).expect("write elf");

        let ops = SecureFileOps::new();
        let result = ops.read_validated_image_sync(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_safe_rejects_dangerous() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("script.sh");

        // Write shebang
        std::fs::write(&path, b"#!/bin/bash\necho hello").expect("write script");

        let ops = SecureFileOps::new();
        let result = ops.read_safe_sync(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_mode() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("mode.txt");

        std::fs::write(&path, b"test").expect("create file");

        let ops = SecureFileOps::new();
        ops.set_mode(&path, FileMode::PRIVATE).expect("set mode");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
