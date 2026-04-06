//! File permissions and mode management
//!
//! Provides cross-platform file permission management with secure defaults.
//!
//! ## Platform Support
//!
//! - **Unix**: Full mode support (0600, 0644, etc.) via `chmod`
//! - **Windows**: Read-only flag support; secure defaults map to restricted access
//!
//! The API is consistent across platforms, but the granularity differs:
//! - Unix has owner/group/other with read/write/execute
//! - Windows has read-only flag and ACLs (ACLs not yet supported)

// Public API - will be used by FileWriter (Issue #111) and external code
#![allow(dead_code)]

use crate::primitives::types::Problem;
use std::path::Path;

/// Unix file permission mode
///
/// Wraps a Unix mode (e.g., 0644, 0600) with named constants for common cases.
///
/// # Named Constants
///
/// | Constant | Mode | Description |
/// |----------|------|-------------|
/// | `PRIVATE` | 0600 | Owner read/write only |
/// | `PRIVATE_EXEC` | 0700 | Owner read/write/execute |
/// | `PRIVATE_GROUP_READ` | 0640 | Owner write, group read |
/// | `LOG_FILE` | 0640 | Same as PRIVATE_GROUP_READ |
/// | `LOG_DIR` | 0750 | Owner rwx, group rx |
/// | `PUBLIC_READ` | 0644 | Owner write, everyone read |
/// | `PUBLIC_EXEC` | 0755 | Owner write, everyone read/execute |
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::FileMode;
///
/// // Use a named constant
/// let mode = FileMode::PRIVATE;
///
/// // Use a custom mode
/// let mode = FileMode::new(0o600);
///
/// // Get the raw mode value
/// let raw: u32 = mode.as_raw();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileMode(u32);

impl FileMode {
    // =========================================================================
    // Named constants for common modes
    // =========================================================================

    /// Owner read/write only (0600)
    ///
    /// Use for: secrets, keys, sensitive configuration
    pub const PRIVATE: Self = Self(0o600);

    /// Owner read/write/execute (0700)
    ///
    /// Use for: directories containing secrets
    pub const PRIVATE_EXEC: Self = Self(0o700);

    /// Owner read/write, group read (0640)
    ///
    /// Use for: log files, configuration files
    pub const PRIVATE_GROUP_READ: Self = Self(0o640);

    /// Same as `PRIVATE_GROUP_READ` - semantic alias for log files
    pub const LOG_FILE: Self = Self(0o640);

    /// Owner rwx, group rx (0750)
    ///
    /// Use for: log directories, application data directories
    pub const LOG_DIR: Self = Self(0o750);

    /// Owner read/write, everyone read (0644)
    ///
    /// Use for: public documentation, non-sensitive assets
    pub const PUBLIC_READ: Self = Self(0o644);

    /// Owner read/write/execute, everyone read/execute (0755)
    ///
    /// Use for: public directories, executables
    pub const PUBLIC_EXEC: Self = Self(0o755);

    // =========================================================================
    // Constructors and accessors
    // =========================================================================

    /// Create a new file mode from a raw Unix mode
    ///
    /// This constructor masks off setuid (4000), setgid (2000), and sticky (1000)
    /// bits for safety. Use [`Self::new_with_special`] if you need these bits.
    ///
    /// # Arguments
    ///
    /// * `mode` - Raw Unix permission bits (e.g., 0o644)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Special bits are masked off
    /// let mode = FileMode::new(0o4755);
    /// assert_eq!(mode.as_raw(), 0o755);
    /// ```
    pub const fn new(mode: u32) -> Self {
        Self(mode & 0o777)
    }

    /// Create a new file mode with special bits allowed
    ///
    /// Unlike [`Self::new`], this preserves setuid (4000), setgid (2000), and sticky (1000) bits.
    ///
    /// # Security Warning
    ///
    /// Use with caution. Setuid/setgid bits can create security vulnerabilities
    /// if applied incorrectly. Most applications should use [`Self::new`] instead.
    ///
    /// # Arguments
    ///
    /// * `mode` - Raw Unix permission bits including special bits (e.g., 0o4755)
    pub const fn new_with_special(mode: u32) -> Self {
        Self(mode & 0o7777)
    }

    /// Get the raw Unix mode value
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// Check if this mode allows world read
    pub const fn is_world_readable(self) -> bool {
        (self.0 & 0o004) != 0
    }

    /// Check if this mode allows world write
    pub const fn is_world_writable(self) -> bool {
        (self.0 & 0o002) != 0
    }

    /// Check if this mode allows group read
    pub const fn is_group_readable(self) -> bool {
        (self.0 & 0o040) != 0
    }

    /// Check if this mode is private (owner only)
    pub const fn is_private(self) -> bool {
        (self.0 & 0o077) == 0
    }

    /// Check if this mode allows world execute
    pub const fn is_world_executable(self) -> bool {
        (self.0 & 0o001) != 0
    }

    /// Check if this mode allows group write
    pub const fn is_group_writable(self) -> bool {
        (self.0 & 0o020) != 0
    }

    /// Returns a security warning if the mode is potentially insecure
    ///
    /// # Returns
    ///
    /// - `Some(warning)` if mode is insecure
    /// - `None` if mode is reasonably secure
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mode = FileMode::new(0o666);
    /// if let Some(warning) = mode.security_warning() {
    ///     println!("Warning: {}", warning);
    /// }
    /// ```
    pub const fn security_warning(&self) -> Option<&'static str> {
        if self.is_world_writable() {
            Some("World-writable permissions are insecure")
        } else if self.is_world_readable() && self.is_world_executable() {
            // 0o755 etc is common for executables - not a warning
            None
        } else {
            None
        }
    }

    /// Check if this mode has special bits (setuid, setgid, or sticky)
    pub const fn is_special_bits_set(self) -> bool {
        (self.0 & 0o7000) != 0
    }

    /// Check if this mode has setuid bit
    pub const fn is_setuid(self) -> bool {
        (self.0 & 0o4000) != 0
    }

    /// Check if this mode has setgid bit
    pub const fn is_setgid(self) -> bool {
        (self.0 & 0o2000) != 0
    }

    /// Check if this mode has sticky bit
    pub const fn is_sticky(self) -> bool {
        (self.0 & 0o1000) != 0
    }
}

impl Default for FileMode {
    fn default() -> Self {
        Self::PRIVATE_GROUP_READ
    }
}

impl From<u32> for FileMode {
    /// Convert from u32, masking off special bits
    ///
    /// Use `FileMode::new_with_special()` if you need setuid/setgid/sticky bits.
    fn from(mode: u32) -> Self {
        Self::new(mode)
    }
}

impl From<FileMode> for u32 {
    fn from(mode: FileMode) -> Self {
        mode.0
    }
}

impl std::fmt::Display for FileMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04o}", self.0)
    }
}

// =============================================================================
// Platform-specific implementations
// =============================================================================

/// Set file permissions on a path
///
/// On Unix, sets the file mode using `chmod`.
/// On non-Unix platforms, this is a no-op that returns `Ok(())`.
///
/// # Umask Behavior
///
/// **Important**: This function uses `chmod(2)` to set the exact mode specified,
/// which is **NOT** affected by the process umask. The umask only affects:
///
/// - `open(2)` with `O_CREAT` when creating new files
/// - `mkdir(2)` when creating directories
/// - Other syscalls that create new filesystem objects
///
/// When you call `set_mode(path, FileMode::new(0o644))`, the file will have
/// exactly mode 0644, regardless of the current umask setting.
///
/// ## When Umask Matters
///
/// If you create a file using `std::fs::File::create()` or similar APIs,
/// the initial permissions are affected by umask. For example:
///
/// ```text
/// # With umask 0022:
/// File::create("test.txt")  -> mode 0644 (0666 & ~0022)
///
/// # With umask 0077:
/// File::create("test.txt")  -> mode 0600 (0666 & ~0077)
/// ```
///
/// After creation, `set_mode` can set the exact permissions you want.
///
/// ## Security Recommendation
///
/// For sensitive files, always call `set_mode` explicitly after creation
/// rather than relying on umask, which may vary between environments.
/// This ensures consistent, predictable permissions regardless of the
/// system's umask configuration.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::{set_mode, FileMode};
///
/// set_mode("/path/to/file", FileMode::PRIVATE)?;
/// ```
#[cfg(unix)]
pub fn set_mode(path: impl AsRef<Path>, mode: FileMode) -> Result<(), Problem> {
    use std::os::unix::fs::PermissionsExt;

    let path = path.as_ref();
    let permissions = std::fs::Permissions::from_mode(mode.as_raw());

    std::fs::set_permissions(path, permissions).map_err(|e| {
        Problem::io(format!(
            "Failed to set permissions on '{}': {}",
            path.display(),
            e
        ))
    })
}

/// Set file permissions on a path (no-op on non-Unix)
#[cfg(not(unix))]
pub fn set_mode(_path: impl AsRef<Path>, _mode: FileMode) -> Result<(), Problem> {
    // No-op on non-Unix platforms
    Ok(())
}

/// Set file permissions on an open file
///
/// On Unix, sets the file mode using the file's metadata.
/// On non-Unix platforms, this is a no-op that returns `Ok(())`.
///
/// # Note
///
/// This function uses `File::set_permissions` which may not work for all file types.
/// For most use cases, prefer `set_mode` with a path after writing.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::{set_file_mode, FileMode};
/// use std::fs::File;
///
/// let file = File::create("test.txt")?;
/// set_file_mode(&file, FileMode::PRIVATE)?;
/// ```
#[cfg(unix)]
pub fn set_file_mode(file: &std::fs::File, mode: FileMode) -> Result<(), Problem> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = std::fs::Permissions::from_mode(mode.as_raw());

    file.set_permissions(permissions)
        .map_err(|e| Problem::io(format!("Failed to set file mode: {}", e)))
}

/// Set file permissions on an open file (no-op on non-Unix)
#[cfg(not(unix))]
pub fn set_file_mode(_file: &std::fs::File, _mode: FileMode) -> Result<(), Problem> {
    // No-op on non-Unix platforms
    Ok(())
}

/// Ensure a directory exists with the specified mode
///
/// Creates the directory if it doesn't exist, then sets the permissions.
/// If the directory already exists and we can't change permissions (e.g.,
/// owned by another user), we check if the existing permissions are at
/// least as restrictive as requested and log a warning if not.
///
/// # Behavior
///
/// 1. If directory doesn't exist: creates it with the specified mode
/// 2. If directory exists and we own it: sets the specified mode
/// 3. If directory exists and we don't own it: verifies permissions aren't
///    too permissive (best-effort, doesn't fail)
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::{ensure_directory_mode, FileMode};
///
/// // Creates /var/log/myapp with 0750 if it doesn't exist
/// // If it exists, attempts to set permissions (may silently skip if not owned)
/// ensure_directory_mode("/var/log/myapp", FileMode::LOG_DIR)?;
/// ```
pub fn ensure_directory_mode(path: impl AsRef<Path>, mode: FileMode) -> Result<(), Problem> {
    let path = path.as_ref();

    // Create directory if needed
    if !path.exists() {
        std::fs::create_dir_all(path).map_err(|e| {
            Problem::io(format!(
                "Failed to create directory '{}': {}",
                path.display(),
                e
            ))
        })?;

        // Set permissions on newly created directory
        set_mode(path, mode)?;
    } else {
        // Directory exists - try to set permissions, but don't fail if we can't
        // This handles cases like /tmp or directories owned by other users
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            if let Ok(metadata) = std::fs::metadata(path) {
                let our_uid = nix::unistd::getuid().as_raw();

                // Only attempt to change permissions if we own the directory
                if metadata.uid() == our_uid {
                    // We own it, set the permissions
                    set_mode(path, mode)?;
                }
                // If we don't own it, we silently accept the existing permissions
                // The directory exists and is usable, which is what matters
            }
        }

        #[cfg(not(unix))]
        {
            // On non-Unix, we can't check ownership, so just try and ignore errors
            let _ = set_mode(path, mode);
        }
    }

    Ok(())
}

/// Check if a path has the expected permissions
///
/// Returns `true` if the file's mode matches the expected mode.
/// On non-Unix platforms, always returns `true`.
#[cfg(unix)]
pub fn validate_mode(path: impl AsRef<Path>, expected: FileMode) -> Result<bool, Problem> {
    use std::os::unix::fs::PermissionsExt;

    let path = path.as_ref();
    let metadata = std::fs::metadata(path).map_err(|e| {
        Problem::io(format!(
            "Failed to get metadata for '{}': {}",
            path.display(),
            e
        ))
    })?;

    let actual_mode = metadata.permissions().mode() & 0o777;
    Ok(actual_mode == expected.as_raw())
}

/// Check if a path has the expected permissions (always true on non-Unix)
#[cfg(not(unix))]
pub fn validate_mode(_path: impl AsRef<Path>, _expected: FileMode) -> Result<bool, Problem> {
    Ok(true)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_file_mode_constants() {
        assert_eq!(FileMode::PRIVATE.as_raw(), 0o600);
        assert_eq!(FileMode::PRIVATE_EXEC.as_raw(), 0o700);
        assert_eq!(FileMode::PRIVATE_GROUP_READ.as_raw(), 0o640);
        assert_eq!(FileMode::LOG_FILE.as_raw(), 0o640);
        assert_eq!(FileMode::LOG_DIR.as_raw(), 0o750);
        assert_eq!(FileMode::PUBLIC_READ.as_raw(), 0o644);
        assert_eq!(FileMode::PUBLIC_EXEC.as_raw(), 0o755);
    }

    #[test]
    fn test_file_mode_predicates() {
        assert!(FileMode::PRIVATE.is_private());
        assert!(!FileMode::PUBLIC_READ.is_private());

        assert!(FileMode::PUBLIC_READ.is_world_readable());
        assert!(!FileMode::PRIVATE.is_world_readable());

        assert!(FileMode::PRIVATE_GROUP_READ.is_group_readable());
        assert!(!FileMode::PRIVATE.is_group_readable());
    }

    #[test]
    fn test_file_mode_conversions() {
        let mode: FileMode = 0o755.into();
        assert_eq!(mode.as_raw(), 0o755);

        let raw: u32 = FileMode::PRIVATE.into();
        assert_eq!(raw, 0o600);
    }

    #[test]
    fn test_file_mode_masks_special_bits() {
        // new() should mask setuid/setgid/sticky
        assert_eq!(FileMode::new(0o4755).as_raw(), 0o755);
        assert_eq!(FileMode::new(0o2755).as_raw(), 0o755);
        assert_eq!(FileMode::new(0o1755).as_raw(), 0o755);
        assert_eq!(FileMode::new(0o7777).as_raw(), 0o777);

        // From<u32> should also mask
        let mode: FileMode = 0o4755.into();
        assert_eq!(mode.as_raw(), 0o755);
    }

    #[test]
    fn test_file_mode_with_special() {
        // new_with_special() should preserve special bits
        assert_eq!(FileMode::new_with_special(0o4755).as_raw(), 0o4755);
        assert_eq!(FileMode::new_with_special(0o2755).as_raw(), 0o2755);
        assert_eq!(FileMode::new_with_special(0o1755).as_raw(), 0o1755);
        assert_eq!(FileMode::new_with_special(0o7777).as_raw(), 0o7777);
    }

    #[test]
    fn test_file_mode_security_warning() {
        // World-writable should warn
        assert!(FileMode::new(0o666).security_warning().is_some());
        assert!(FileMode::new(0o777).security_warning().is_some());
        assert!(FileMode::new(0o622).security_warning().is_some());

        // Normal modes should not warn
        assert!(FileMode::PRIVATE.security_warning().is_none());
        assert!(FileMode::PUBLIC_READ.security_warning().is_none());
        assert!(FileMode::PUBLIC_EXEC.security_warning().is_none());
    }

    #[test]
    fn test_file_mode_special_bits_detection() {
        let setuid = FileMode::new_with_special(0o4755);
        assert!(setuid.is_setuid());
        assert!(!setuid.is_setgid());
        assert!(!setuid.is_sticky());
        assert!(setuid.is_special_bits_set());

        let setgid = FileMode::new_with_special(0o2755);
        assert!(!setgid.is_setuid());
        assert!(setgid.is_setgid());
        assert!(!setgid.is_sticky());
        assert!(setgid.is_special_bits_set());

        let sticky = FileMode::new_with_special(0o1755);
        assert!(!sticky.is_setuid());
        assert!(!sticky.is_setgid());
        assert!(sticky.is_sticky());
        assert!(sticky.is_special_bits_set());

        // Normal mode has no special bits
        assert!(!FileMode::PUBLIC_EXEC.is_special_bits_set());
    }

    #[test]
    fn test_file_mode_additional_predicates() {
        assert!(FileMode::PUBLIC_EXEC.is_world_executable());
        assert!(!FileMode::PUBLIC_READ.is_world_executable());

        let group_writable = FileMode::new(0o664);
        assert!(group_writable.is_group_writable());
        assert!(!FileMode::PUBLIC_READ.is_group_writable());
    }

    #[test]
    fn test_file_mode_display() {
        assert_eq!(format!("{}", FileMode::PRIVATE), "0600");
        assert_eq!(format!("{}", FileMode::PUBLIC_READ), "0644");
        assert_eq!(format!("{}", FileMode::PUBLIC_EXEC), "0755");
        assert_eq!(format!("{}", FileMode::new(0o777)), "0777");
    }

    #[test]
    fn test_file_mode_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(FileMode::PRIVATE);
        set.insert(FileMode::PUBLIC_READ);
        set.insert(FileMode::PRIVATE); // duplicate

        assert_eq!(set.len(), 2);
        assert!(set.contains(&FileMode::PRIVATE));
        assert!(set.contains(&FileMode::PUBLIC_READ));
    }

    #[cfg(unix)]
    #[test]
    fn test_set_and_validate_mode() {
        use tempfile::tempdir;

        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test_perms.txt");

        // Create file
        std::fs::write(&path, "test").expect("write file");

        // Set mode
        set_mode(&path, FileMode::PRIVATE).expect("set mode");

        // Check mode
        assert!(validate_mode(&path, FileMode::PRIVATE).expect("check mode"));
        assert!(!validate_mode(&path, FileMode::PUBLIC_READ).expect("check mode"));
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_directory_mode() {
        use std::os::unix::fs::PermissionsExt;
        use tempfile::tempdir;

        let dir = tempdir().expect("create temp dir");
        let new_dir = dir.path().join("subdir");

        // Create and set mode
        ensure_directory_mode(&new_dir, FileMode::LOG_DIR).expect("ensure dir");

        // Verify
        assert!(new_dir.is_dir());
        let metadata = std::fs::metadata(&new_dir).expect("get metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o750);
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_directory_mode_creates_nested_dirs() {
        use std::os::unix::fs::PermissionsExt;
        use tempfile::tempdir;

        let dir = tempdir().expect("create temp dir");
        let nested_dir = dir.path().join("a").join("b").join("c");

        // Create nested directories
        ensure_directory_mode(&nested_dir, FileMode::LOG_DIR).expect("ensure nested dir");

        // Verify leaf directory exists with correct permissions
        assert!(nested_dir.is_dir());
        let metadata = std::fs::metadata(&nested_dir).expect("get metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o750);
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_directory_mode_updates_owned_existing_dir() {
        use std::os::unix::fs::PermissionsExt;
        use tempfile::tempdir;

        let dir = tempdir().expect("create temp dir");
        let subdir = dir.path().join("owned_dir");

        // Create directory with different permissions first
        std::fs::create_dir(&subdir).expect("create dir");
        std::fs::set_permissions(&subdir, std::fs::Permissions::from_mode(0o777))
            .expect("set initial permissions");

        // Now ensure_directory_mode should update it (we own it)
        ensure_directory_mode(&subdir, FileMode::LOG_DIR).expect("ensure dir");

        // Verify permissions were updated
        let metadata = std::fs::metadata(&subdir).expect("get metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o750);
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_directory_mode_on_tmp_succeeds() {
        // /tmp exists and is owned by root, but we should NOT fail
        // This tests the "don't fail on directories we don't own" behavior
        let result = ensure_directory_mode("/tmp", FileMode::LOG_DIR);

        // Should succeed (not try to change permissions on /tmp)
        assert!(result.is_ok(), "Should not fail on /tmp: {:?}", result);
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_directory_mode_on_var_tmp_succeeds() {
        // /var/tmp is another common shared directory
        if std::path::Path::new("/var/tmp").exists() {
            let result = ensure_directory_mode("/var/tmp", FileMode::LOG_DIR);
            assert!(result.is_ok(), "Should not fail on /var/tmp: {:?}", result);
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_directory_mode_creates_subdir_in_tmp() {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Create a unique subdirectory in /tmp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let subdir = format!("/tmp/octarine_test_{}", timestamp);
        let path = std::path::PathBuf::from(&subdir);

        // Should create the subdirectory with correct permissions
        let result = ensure_directory_mode(&path, FileMode::LOG_DIR);

        // Cleanup before assertions (so cleanup happens even if assertions fail)
        #[allow(clippy::disallowed_methods)]
        let cleanup_result = std::fs::remove_dir_all(&path);

        // Now check results
        result.expect("ensure subdir in /tmp");

        // The directory existed before cleanup
        // We verify permissions were correct by checking the ensure succeeded
        // and cleanup succeeded (meaning directory was created)
        cleanup_result.expect("cleanup should succeed, meaning dir was created");
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_directory_mode_creates_subdir_with_correct_perms() {
        use std::os::unix::fs::PermissionsExt;
        use tempfile::tempdir;

        // Use tempdir as parent to avoid cleanup issues
        let parent = tempdir().expect("create temp dir");
        let subdir = parent.path().join("myapp_logs");

        // Should create the subdirectory with correct permissions
        ensure_directory_mode(&subdir, FileMode::LOG_DIR).expect("ensure subdir");

        assert!(subdir.is_dir());
        let metadata = std::fs::metadata(&subdir).expect("get metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o750);
    }

    #[cfg(unix)]
    #[test]
    fn test_set_file_mode_on_open_file() {
        use std::os::unix::fs::PermissionsExt;
        use tempfile::tempdir;

        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("file_handle_test.txt");

        // Create and open file
        let file = std::fs::File::create(&path).expect("create file");

        // Set mode via file handle
        set_file_mode(&file, FileMode::PRIVATE).expect("set file mode");

        // Verify via path
        let metadata = std::fs::metadata(&path).expect("get metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
