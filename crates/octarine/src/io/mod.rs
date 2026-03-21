//! Secure I/O operations with built-in observability
//!
//! This module provides secure file and network I/O operations with automatic
//! audit trails, metrics, and compliance support. All operations wrap primitives
//! with observe instrumentation.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      io/ (Public API)                       │
//! │  - SecureTempFile, write_atomic, FileMode                   │
//! │  - Magic byte validation, secure delete                     │
//! │  - Shortcuts for common operations                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │                  primitives/io/ (Internal)                  │
//! │  - Pure atomic writes, locking, permissions                 │
//! │  - Magic byte detection, no logging                         │
//! ├─────────────────────────────────────────────────────────────┤
//! │                    observe/ (Internal)                      │
//! │  - Logging, metrics, tracing                                │
//! │  - Audit trail for compliance                               │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Types
//!
//! ## File Operations
//! - `FileMode` - Unix file permission modes
//! - `WriteOptions` - Configuration for atomic writes
//! - `write_atomic` - Atomic file write with audit trail
//! - `set_mode` - Set file permissions
//!
//! ## Temporary Files
//! - `SecureTempFile` - Secure temporary file with auto-cleanup
//! - `SecureTempFileBuilder` - Builder for configuring temp files
//!
//! ## Secure Deletion
//! - `SecureDelete` - Secure file deletion with compliance support
//! - `DeleteMethod` - Deletion methods (NIST, DoD, etc.)
//! - `secure_delete` - Quick secure deletion function
//!
//! ## Magic Byte Detection
//! - `MagicFileType` - Detected file type from magic bytes
//! - `detect_magic` - Detect file type from bytes
//! - `validate_file_type` - Validate file matches expected type
//!
//! ## Secure File Operations
//! - `SecureFileOps` - High-level secure file operations
//!
//! # Examples
//!
//! ## Atomic File Writes
//!
//! ```ignore
//! use octarine::io::{write_atomic, WriteOptions};
//!
//! // Simple atomic write with audit trail
//! write_atomic("config.json", b"{}", WriteOptions::default())?;
//!
//! // Write secrets with restricted permissions
//! write_atomic(".env", b"SECRET=value", WriteOptions::for_secrets())?;
//! ```
//!
//! ## Secure Temp Files
//!
//! ```ignore
//! use octarine::io::SecureTempFile;
//!
//! // Create temp file with secure defaults (0600 permissions)
//! let mut temp = SecureTempFile::new().await?;
//! temp.write_all(b"temporary data")?;
//!
//! // Or use the builder for more control
//! let mut temp = SecureTempFile::builder()
//!     .prefix("myapp-")
//!     .suffix(".env")
//!     .secure_delete(true)
//!     .build().await?;
//!
//! // File is automatically deleted on drop
//! ```
//!
//! ## Secure File Deletion
//!
//! ```ignore
//! use octarine::io::{SecureDelete, DeleteMethod, secure_delete};
//!
//! // Quick secure deletion (NIST 800-88)
//! secure_delete("/path/to/secret.txt").await?;
//!
//! // DoD-compliant deletion with verification
//! SecureDelete::new("/path/to/classified.doc").await?
//!     .method(DeleteMethod::Dod522022M)
//!     .verify(true)
//!     .execute().await?;
//! ```

// Private submodules (two-layer API: octarine::io::*, not octarine::io::file::*)
mod delete;
mod file;
mod magic;
mod ops;
mod temp;

#[cfg(feature = "formats")]
pub mod formats;

// Re-export file module contents at io level for convenience
pub use file::{
    // Types
    FileMode,
    WriteOptions,
    // Permissions
    set_mode,
    // Atomic operations
    write_atomic,
};

// Re-export temp module contents
pub use temp::{SecureTempFile, SecureTempFileBuilder};

// Re-export delete module contents
#[allow(unused_imports)]
pub use delete::{
    // Types
    DeleteMethod,
    SecureDelete,
    SecureDeleteResult,
    // Async convenience functions (default)
    secure_delete,
    secure_delete_dod,
    // Sync: use SecureDelete::new_sync()?.execute_sync() directly
};

// Re-export magic module contents
// Allow unused - these are public APIs for library consumers
#[allow(unused_imports)]
pub use magic::{
    // Types
    MagicFileType,
    MagicResult,
    // File-based detection (async - default)
    detect_file_type,
    // File-based detection (sync - explicit opt-in)
    detect_file_type_sync,
    // In-memory detection (sync, no I/O)
    detect_magic,
    is_archive_file,
    is_archive_file_sync,
    is_archive_magic,
    is_dangerous_file,
    is_dangerous_file_sync,
    is_dangerous_magic,
    is_executable_file,
    is_executable_file_sync,
    is_executable_magic,
    is_image_file,
    is_image_file_sync,
    is_image_magic,
    // Validation (async - default)
    validate_extension_matches,
    // Validation (sync - explicit opt-in)
    validate_extension_matches_sync,
    validate_file_type,
    validate_file_type_sync,
    validate_image,
    validate_image_sync,
    validate_not_dangerous,
    validate_not_dangerous_sync,
};

// Re-export SecureFileOps
#[allow(unused_imports)]
pub use ops::{AuditLevel, SecureFileOps, SecureFileOpsBuilder, SecureFileOpsConfig};
