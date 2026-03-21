//! Secure file operations with observability
//!
//! Wraps `primitives::io::file` with observe instrumentation for audit trails,
//! metrics, and compliance-grade logging.
//!
//! # Features
//!
//! - **Atomic Writes**: Write-to-temp → fsync → rename pattern
//! - **Permissions**: Secure file modes with platform abstraction
//! - **Audit Trails**: All operations logged via observe
//! - **Metrics**: Operation counts, durations, and sizes
//!
//! # Examples
//!
//! ```ignore
//! use octarine::io::{write_atomic, WriteOptions, FileMode};
//!
//! // Atomic write with audit trail
//! write_atomic("config.json", b"{}", WriteOptions::default())?;
//!
//! // Write secrets (0600 permissions)
//! write_atomic(".env", b"SECRET=value", WriteOptions::for_secrets())?;
//!
//! // Custom permissions
//! let opts = WriteOptions::default().mode(FileMode::PRIVATE);
//! write_atomic("private.txt", b"data", opts)?;
//! ```

use std::path::Path;

use crate::observe::{self, Problem};
use crate::primitives::io::file as prim;

// Re-export types from primitives (no wrapping needed for pure types)
pub use prim::{FileMode, WriteOptions};

/// Write data to a file atomically with audit trail
///
/// Uses the write-to-temp → fsync → rename pattern to ensure atomic writes.
/// All operations are logged via observe for compliance.
///
/// # Arguments
///
/// * `path` - Target file path
/// * `data` - Data to write
/// * `options` - Write options (mode, sync, etc.)
///
/// # Examples
///
/// ```ignore
/// use octarine::io::{write_atomic, WriteOptions};
///
/// // Simple write
/// write_atomic("file.txt", b"content", WriteOptions::default())?;
///
/// // Write with secrets permissions (0600)
/// write_atomic(".env", b"SECRET=x", WriteOptions::for_secrets())?;
/// ```
///
/// # Errors
///
/// Returns `Problem::Io` if the write fails.
pub fn write_atomic(
    path: impl AsRef<Path>,
    data: &[u8],
    options: WriteOptions,
) -> Result<(), Problem> {
    let path = path.as_ref();
    let path_str = path.display().to_string();
    let data_len = data.len();

    observe::debug(
        "io.file.write_atomic",
        format!("Writing {} bytes to {}", data_len, path_str),
    );

    let result = prim::write_atomic(path, data, options);

    match &result {
        Ok(()) => {
            observe::info(
                "io.file.write_atomic",
                format!("Wrote {} bytes to {}", data_len, path_str),
            );
        }
        Err(e) => {
            observe::warn(
                "io.file.write_atomic",
                format!("Failed to write to {}: {}", path_str, e),
            );
        }
    }

    result
}

/// Set file permissions with audit trail
///
/// # Arguments
///
/// * `path` - File path
/// * `mode` - Permission mode to set
///
/// # Examples
///
/// ```ignore
/// use octarine::io::{set_mode, FileMode};
///
/// set_mode("secret.txt", FileMode::PRIVATE)?;
/// ```
pub fn set_mode(path: impl AsRef<Path>, mode: FileMode) -> Result<(), Problem> {
    let path = path.as_ref();
    let path_str = path.display().to_string();

    observe::debug(
        "io.file.set_mode",
        format!("Setting mode {:o} on {}", mode.as_raw(), path_str),
    );

    let result = prim::set_mode(path, mode);

    match &result {
        Ok(()) => {
            observe::debug(
                "io.file.set_mode",
                format!("Set mode {:o} on {}", mode.as_raw(), path_str),
            );
        }
        Err(e) => {
            observe::warn(
                "io.file.set_mode",
                format!("Failed to set mode on {}: {}", path_str, e),
            );
        }
    }

    result
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]

    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_write_atomic_basic() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");

        write_atomic(&path, b"hello world", WriteOptions::default())
            .expect("atomic write should succeed");

        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "hello world");
    }

    #[test]
    fn test_write_atomic_secrets() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("secret.txt");

        write_atomic(&path, b"secret", WriteOptions::for_secrets())
            .expect("atomic write should succeed");

        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "secret");
    }

    #[cfg(unix)]
    #[test]
    fn test_set_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("mode_test.txt");

        // Create file first
        std::fs::write(&path, b"test").expect("write file");

        // Set mode
        set_mode(&path, FileMode::PRIVATE).expect("set mode");

        // Check mode
        let metadata = std::fs::metadata(&path).expect("get metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
