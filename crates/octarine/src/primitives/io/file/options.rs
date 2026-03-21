//! Write options and configuration types
//!
//! Provides configuration for atomic writes with secure defaults.

// Public API - will be used by FileWriter (Issue #111) and external code
#![allow(dead_code)]

use super::permissions::FileMode;

/// Sync mode for durability
///
/// Controls when data is flushed to disk. Higher durability = slower writes.
///
/// # Implementation Note
///
/// The `atomic-write-file` crate internally performs `fsync` on commit for all
/// modes. The distinction between `Data` and `Full` is preserved for:
/// 1. Documentation purposes (expressing intent)
/// 2. Future implementations that may differentiate
/// 3. Semantic clarity when choosing options
///
/// In practice, all modes currently provide full durability on commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum SyncMode {
    /// No explicit sync - rely on OS buffering (fastest, least durable)
    ///
    /// Data may be lost on crash. Only use for non-critical temporary files.
    ///
    /// **Note**: Due to `atomic-write-file` behavior, commit still syncs.
    None,

    /// Sync data only - `fdatasync()` on Unix
    ///
    /// Ensures data reaches disk but metadata (mtime, size) may lag.
    /// Good balance of performance and durability.
    #[default]
    Data,

    /// Full sync - `fsync()` on Unix
    ///
    /// Ensures both data and metadata reach disk.
    /// Slowest but safest option.
    Full,
}

/// Strategy for temp file location
///
/// Determines where the temporary file is created before atomic rename.
///
/// # Current Implementation
///
/// Currently only `SameDirectory` is used by the implementation. The `SystemTemp`
/// variant is reserved for future use cases where atomic rename is not required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum TempStrategy {
    /// Create temp file in same directory as target (default)
    ///
    /// Required for atomic rename to work (same filesystem).
    /// Temp file is automatically cleaned up on crash via O_TMPFILE on Linux.
    #[default]
    SameDirectory,

    /// Create temp file in system temp directory
    ///
    /// **Warning**: May not be on same filesystem, making atomic rename impossible.
    /// Falls back to copy+delete if rename fails.
    ///
    /// **Note**: Currently unused - reserved for future non-atomic write scenarios.
    #[allow(dead_code)]
    SystemTemp,
}

/// Options for atomic file writes
///
/// All defaults are secure - users must explicitly opt-in to less secure options.
///
/// # Defaults (Secure)
///
/// - `mode`: `FileMode::PRIVATE_GROUP_READ` (0640) - owner write, group read
/// - `sync`: `SyncMode::Data` - sync data to disk
/// - `temp_strategy`: `TempStrategy::SameDirectory` - atomic rename works
/// - `follow_symlinks`: `false` - prevent symlink attacks
/// - `overwrite`: `true` - allow overwriting existing files
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::{WriteOptions, FileMode, SyncMode};
///
/// // Secure defaults
/// let opts = WriteOptions::default();
///
/// // Custom options
/// let opts = WriteOptions::default()
///     .mode(FileMode::PRIVATE)
///     .sync(SyncMode::Full);
///
/// // Preset for log files
/// let opts = WriteOptions::for_logs();
///
/// // Preset for secrets
/// let opts = WriteOptions::for_secrets();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WriteOptions {
    /// File permissions (Unix mode)
    pub mode: FileMode,

    /// Sync mode for durability
    pub sync: SyncMode,

    /// Where to create temp file
    pub temp_strategy: TempStrategy,

    /// Whether to follow symlinks when writing
    ///
    /// Default: `false` (secure - prevents symlink attacks)
    pub follow_symlinks: bool,

    /// Whether to allow overwriting existing files
    pub overwrite: bool,

    /// Whether to preserve existing permissions when overwriting
    pub preserve_permissions: bool,
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self {
            // Secure default: owner read/write, group read
            mode: FileMode::PRIVATE_GROUP_READ,

            // Sync data to disk (not just kernel buffer)
            sync: SyncMode::Data,

            // Same directory for atomic rename
            temp_strategy: TempStrategy::SameDirectory,

            // Don't follow symlinks (prevent attacks)
            follow_symlinks: false,

            // Allow overwriting by default
            overwrite: true,

            // Don't preserve permissions by default (use our secure mode)
            preserve_permissions: false,
        }
    }
}

impl WriteOptions {
    /// Create options with default secure settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Set file permissions
    pub fn mode(mut self, mode: FileMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set sync mode
    pub fn sync(mut self, sync: SyncMode) -> Self {
        self.sync = sync;
        self
    }

    /// Set temp file strategy
    pub fn temp_strategy(mut self, strategy: TempStrategy) -> Self {
        self.temp_strategy = strategy;
        self
    }

    /// Set whether to follow symlinks
    ///
    /// **Warning**: Setting this to `true` can enable symlink attacks.
    pub fn follow_symlinks(mut self, follow: bool) -> Self {
        self.follow_symlinks = follow;
        self
    }

    /// Set whether to allow overwriting
    pub fn overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }

    /// Set whether to preserve existing permissions
    pub fn preserve_permissions(mut self, preserve: bool) -> Self {
        self.preserve_permissions = preserve;
        self
    }

    // =========================================================================
    // Presets for common use cases
    // =========================================================================

    /// Options for log files
    ///
    /// - Mode: 0640 (owner write, group read)
    /// - Sync: Data (balance durability and performance)
    pub fn for_logs() -> Self {
        Self::default().mode(FileMode::LOG_FILE)
    }

    /// Options for configuration files
    ///
    /// - Mode: 0640 (owner write, group read)
    /// - Sync: Full (ensure config is durable)
    /// - Preserve permissions: true (don't change existing perms)
    pub fn for_config() -> Self {
        Self::default()
            .mode(FileMode::PRIVATE_GROUP_READ)
            .sync(SyncMode::Full)
            .preserve_permissions(true)
    }

    /// Options for secret/key files
    ///
    /// - Mode: 0600 (owner only)
    /// - Sync: Full (ensure secrets are durable)
    pub fn for_secrets() -> Self {
        Self::default().mode(FileMode::PRIVATE).sync(SyncMode::Full)
    }

    /// Options for temporary/cache files
    ///
    /// - Mode: 0600 (owner only)
    /// - Sync: None (speed over durability)
    pub fn for_temp() -> Self {
        Self::default().mode(FileMode::PRIVATE).sync(SyncMode::None)
    }

    /// Options for user-uploaded files
    ///
    /// - Mode: 0640 (owner write, group read)
    /// - Sync: Data (reasonable durability)
    /// - Overwrite: false (don't overwrite existing)
    pub fn for_uploads() -> Self {
        Self::default()
            .mode(FileMode::PRIVATE_GROUP_READ)
            .sync(SyncMode::Data)
            .overwrite(false)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_default_is_secure() {
        let opts = WriteOptions::default();

        // Restrictive permissions
        assert_eq!(opts.mode, FileMode::PRIVATE_GROUP_READ);

        // Data sync (not none)
        assert_eq!(opts.sync, SyncMode::Data);

        // No symlink following
        assert!(!opts.follow_symlinks);

        // Same directory for atomic rename
        assert_eq!(opts.temp_strategy, TempStrategy::SameDirectory);
    }

    #[test]
    fn test_builder_pattern() {
        let opts = WriteOptions::default()
            .mode(FileMode::PRIVATE)
            .sync(SyncMode::Full)
            .follow_symlinks(true)
            .overwrite(false);

        assert_eq!(opts.mode, FileMode::PRIVATE);
        assert_eq!(opts.sync, SyncMode::Full);
        assert!(opts.follow_symlinks);
        assert!(!opts.overwrite);
    }

    #[test]
    fn test_presets() {
        // Logs
        let logs = WriteOptions::for_logs();
        assert_eq!(logs.mode, FileMode::LOG_FILE);
        assert_eq!(logs.sync, SyncMode::Data);

        // Config
        let config = WriteOptions::for_config();
        assert_eq!(config.sync, SyncMode::Full);
        assert!(config.preserve_permissions);

        // Secrets
        let secrets = WriteOptions::for_secrets();
        assert_eq!(secrets.mode, FileMode::PRIVATE);
        assert_eq!(secrets.sync, SyncMode::Full);

        // Temp
        let temp = WriteOptions::for_temp();
        assert_eq!(temp.sync, SyncMode::None);

        // Uploads
        let uploads = WriteOptions::for_uploads();
        assert!(!uploads.overwrite);
    }
}
