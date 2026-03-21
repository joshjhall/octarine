//! Secure File I/O Primitives
//!
//! Foundation utilities for secure file operations with ZERO internal dependencies.
//! Provides atomic writes, file locking, permissions management, and async filesystem operations.
//!
//! ## Architecture
//!
//! This is **Layer 1 (primitives)** - pure utilities with no observe dependencies.
//! Layer 3 (`octarine::io`) wraps these with observe instrumentation.
//!
//! ## Key Features
//!
//! - **Async Filesystem**: Async-first wrappers for common fs operations (Node.js philosophy)
//! - **Atomic Writes**: Write-to-temp → fsync → rename pattern via `atomic-write-file`
//! - **File Locking**: Cross-platform advisory locking via `fd-lock` (used by Firefox/Servo)
//! - **File Permissions**: Unix file modes with secure defaults (0640 for files, 0750 for dirs)
//! - **Secure Defaults**: All options default to the most secure settings
//!
//! ## Security Philosophy
//!
//! All defaults err on the side of caution:
//! - Restrictive permissions (owner + group, not world-readable)
//! - Sync to disk by default (data durability)
//! - No symlink following (prevent symlink attacks)
//! - Temp files in same directory (atomic rename works)
//!
//! ## Async-First Design
//!
//! Like Node.js, we default to async operations. Use async functions to avoid blocking
//! the runtime, especially in the `observe` module which cannot block the main thread.
//!
//! ```rust,ignore
//! use crate::primitives::io::{path_exists, path_metadata, is_file};
//!
//! // Async (default) - won't block the runtime
//! if path_exists(path.clone()).await? {
//!     let metadata = path_metadata(path).await?;
//!     println!("File size: {}", metadata.len());
//! }
//!
//! // Sync (explicit opt-in) - WILL block the current thread
//! use crate::primitives::io::path_exists_sync;
//! if path_exists_sync(&path) {
//!     // Only use in sync contexts or tests
//! }
//! ```
//!
//! ## Atomic Writes
//!
//! ```rust,ignore
//! use crate::primitives::io::{write_atomic, WriteOptions, FileMode};
//!
//! // Simple atomic write with secure defaults
//! write_atomic(path, data, WriteOptions::default())?;
//!
//! // Custom options for specific use cases
//! write_atomic(path, data, WriteOptions::for_logs())?;
//! write_atomic(path, data, WriteOptions::for_config())?;
//! write_atomic(path, data, WriteOptions::for_secrets())?;
//! ```

// Layer 1 primitives - used by Layer 2/3
#![allow(dead_code)]

mod async_fs;
mod atomic;
mod batched;
mod builder;
mod locking;
mod magic;
mod options;
mod permissions;
mod pidlock;

// Re-export public API
// Allow dead_code - these are public APIs that will be used by FileWriter (Issue #111)
// and external code

// Async filesystem operations (async-first design)
#[allow(unused_imports)]
pub use async_fs::{
    // Async operations (default)
    canonicalize,
    copy_file,
    create_dir_all,
    file_size,
    // Sync variants (explicit opt-in)
    file_size_sync,
    is_dir,
    is_dir_sync,
    is_file,
    is_file_sync,
    is_symlink,
    modified_time,
    path_exists,
    path_exists_sync,
    path_metadata,
    path_metadata_sync,
    read_dir,
    read_file,
    read_file_string,
    read_file_string_sync,
    read_file_sync,
    remove_file,
    rename,
    symlink_metadata,
    write_file,
    write_file_string,
    write_file_sync,
};

#[allow(unused_imports)]
pub use atomic::{AtomicWriter, write_atomic, write_atomic_async};
#[allow(unused_imports)]
pub use batched::BatchedWriter;
#[allow(unused_imports)]
pub use builder::IoBuilder;
#[allow(unused_imports)]
pub use locking::{
    ExclusiveFileLock, LockMode, LockableFile, PortableLock, SharedFileLock, lock_file_exclusive,
    lock_file_exclusive_async, lock_file_portable, lock_file_shared, lock_file_shared_async,
    try_lock_file_portable,
};
#[allow(unused_imports)]
pub use options::{SyncMode, TempStrategy, WriteOptions};
#[allow(unused_imports)]
pub use permissions::{FileMode, ensure_directory_mode, set_file_mode, set_mode};

// Magic byte detection
#[allow(unused_imports)]
pub use magic::{
    MAX_MAGIC_BYTES, MIN_MAGIC_BYTES, MagicFileType, MagicResult, RECOMMENDED_MAGIC_BYTES,
    detect_magic, is_archive_magic, is_dangerous_magic, is_executable_magic, is_image_magic,
};

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
    fn test_write_atomic_overwrites() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");

        // First write
        write_atomic(&path, b"first", WriteOptions::default()).expect("first write");

        // Overwrite
        write_atomic(&path, b"second", WriteOptions::default()).expect("second write");

        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "second");
    }

    #[test]
    fn test_write_options_defaults() {
        let opts = WriteOptions::default();
        assert_eq!(opts.mode, FileMode::PRIVATE_GROUP_READ);
        assert_eq!(opts.sync, SyncMode::Data);
        assert!(!opts.follow_symlinks);
    }

    #[test]
    fn test_write_options_for_logs() {
        let opts = WriteOptions::for_logs();
        assert_eq!(opts.mode, FileMode::LOG_FILE);
    }

    #[test]
    fn test_write_options_for_secrets() {
        let opts = WriteOptions::for_secrets();
        assert_eq!(opts.mode, FileMode::PRIVATE);
    }

    #[cfg(unix)]
    #[test]
    fn test_file_permissions_set() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");

        // Write with specific mode
        let opts = WriteOptions::default().mode(FileMode::PRIVATE);
        write_atomic(&path, b"secret", opts).expect("write with mode");

        let metadata = std::fs::metadata(&path).expect("get metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "file should be owner-only");
    }

    #[test]
    fn test_atomic_writer_commit() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("writer_test.txt");

        {
            let mut writer =
                AtomicWriter::new(&path, WriteOptions::default()).expect("create atomic writer");

            use std::io::Write;
            writer.write_all(b"line 1\n").expect("write line 1");
            writer.write_all(b"line 2\n").expect("write line 2");
            writer.commit().expect("commit");
        }

        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "line 1\nline 2\n");
    }

    #[test]
    fn test_atomic_writer_no_commit_no_file() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("no_commit.txt");

        {
            let mut writer =
                AtomicWriter::new(&path, WriteOptions::default()).expect("create atomic writer");

            use std::io::Write;
            writer.write_all(b"should not persist").expect("write");
            // Drop without commit
        }

        assert!(!path.exists(), "file should not exist without commit");
    }
}
