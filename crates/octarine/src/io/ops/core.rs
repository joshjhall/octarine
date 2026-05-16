//! Core `SecureFileOps` implementation
//!
//! Read/write/info/locked/permission operations plus the private observe-helper
//! methods. The async/sync API symmetry and `Default` impl are preserved
//! exactly as on the unsplit file.

use std::io::{Read, Write};
use std::path::Path;

use crate::observe::metrics::{MetricTimer, timer};
use crate::observe::{self, Problem};
use crate::primitives::io::file::{
    self as prim_file, FileMode, PortableLock, WriteOptions, file_size as prim_file_size,
    file_size_sync as prim_file_size_sync, lock_file_portable, path_exists, path_exists_sync,
    read_file as prim_read_file, read_file_sync as prim_read_file_sync,
};

use crate::io::magic::{
    MagicResult, detect_file_type, detect_file_type_sync, validate_image, validate_image_sync,
    validate_not_dangerous, validate_not_dangerous_sync,
};

use super::builder::SecureFileOpsBuilder;
use super::config::{AuditLevel, SecureFileOpsConfig};

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
    pub(super) config: SecureFileOpsConfig,
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
