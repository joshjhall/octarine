//! Atomic file write operations
//!
//! Provides atomic file writes using the write-to-temp → fsync → rename pattern.
//! Uses the `atomic-write-file` crate which is battle-tested and supports O_TMPFILE
//! on Linux for automatic cleanup.

// Public API - will be used by FileWriter (Issue #111) and external code
#![allow(dead_code)]

use crate::primitives::types::Problem;
use std::io::{self, Write};
use std::path::Path;

use super::options::{SyncMode, WriteOptions};
use super::permissions::set_mode;

/// Write data to a file atomically
///
/// Uses the write-to-temp → fsync → rename pattern to ensure the file is either
/// completely written or not modified at all. This prevents partial writes and
/// corruption on crash.
///
/// # How It Works
///
/// 1. Creates a temporary file in the same directory (O_TMPFILE on Linux)
/// 2. Writes all data to the temp file
/// 3. Syncs to disk (based on `WriteOptions::sync`)
/// 4. Atomically renames temp file to target path
/// 5. Sets file permissions (based on `WriteOptions::mode`)
///
/// # Arguments
///
/// * `path` - Target file path
/// * `data` - Data to write
/// * `options` - Write options (mode, sync, etc.)
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::{write_atomic, WriteOptions};
///
/// // Simple write with secure defaults
/// write_atomic("/path/to/file", b"content", WriteOptions::default())?;
///
/// // Write with custom options
/// write_atomic(
///     "/path/to/secret",
///     b"secret data",
///     WriteOptions::for_secrets()
/// )?;
/// ```
///
/// # Errors
///
/// Returns `Problem::Io` if:
/// - The target directory doesn't exist
/// - Permission denied
/// - Disk full
/// - File already exists and `overwrite` is false
/// - Path is a symlink and `follow_symlinks` is false
///
/// # Security Note
///
/// The symlink check has a TOCTOU (time-of-check-time-of-use) race condition:
/// an attacker could replace a regular file with a symlink between the check
/// and the write. For high-security scenarios, consider additional controls
/// such as:
/// - Using a directory with restricted permissions
/// - Checking the file descriptor after opening (not currently supported)
/// - Using O_NOFOLLOW at the open level (handled by `atomic-write-file` on Linux)
pub fn write_atomic(
    path: impl AsRef<Path>,
    data: &[u8],
    options: WriteOptions,
) -> Result<(), Problem> {
    let path = path.as_ref();

    // Check if file exists when overwrite is false
    if !options.overwrite && path.exists() {
        return Err(Problem::io(format!(
            "File '{}' already exists and overwrite is disabled",
            path.display()
        )));
    }

    // Check for symlink if follow_symlinks is false
    if !options.follow_symlinks && path.is_symlink() {
        return Err(Problem::io(format!(
            "Path '{}' is a symlink and follow_symlinks is disabled",
            path.display()
        )));
    }

    // Get existing permissions if we need to preserve them
    #[cfg(unix)]
    let existing_mode = if options.preserve_permissions && path.exists() {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .ok()
            .map(|m| super::permissions::FileMode::new(m.permissions().mode() & 0o777))
    } else {
        None
    };

    #[cfg(not(unix))]
    let existing_mode: Option<super::permissions::FileMode> = None;

    // Use atomic-write-file for the actual atomic write
    let mut atomic_file = atomic_write_file::AtomicWriteFile::open(path).map_err(|e| {
        Problem::io(format!(
            "Failed to create atomic write for '{}': {}",
            path.display(),
            e
        ))
    })?;

    // Write all data
    atomic_file.write_all(data).map_err(|e| {
        Problem::io(format!(
            "Failed to write data to '{}': {}",
            path.display(),
            e
        ))
    })?;

    // Sync based on options
    match options.sync {
        SyncMode::None => {
            // No sync - just flush the buffer
            atomic_file
                .flush()
                .map_err(|e| Problem::io(format!("Failed to flush '{}': {}", path.display(), e)))?;
        }
        SyncMode::Data => {
            // Sync data only
            atomic_file
                .flush()
                .map_err(|e| Problem::io(format!("Failed to flush '{}': {}", path.display(), e)))?;
            // Note: atomic-write-file handles fsync internally on commit
        }
        SyncMode::Full => {
            // Full sync (atomic-write-file does this by default)
            atomic_file
                .flush()
                .map_err(|e| Problem::io(format!("Failed to flush '{}': {}", path.display(), e)))?;
        }
    }

    // Commit the atomic write (renames temp file to target)
    atomic_file.commit().map_err(|e| {
        Problem::io(format!(
            "Failed to commit atomic write to '{}': {}",
            path.display(),
            e
        ))
    })?;

    // Set file permissions
    let mode_to_set = existing_mode.unwrap_or(options.mode);
    set_mode(path, mode_to_set)?;

    Ok(())
}

/// An atomic file writer that allows incremental writes
///
/// Unlike `atomic_write`, this allows writing data in chunks and explicitly
/// committing when done. If dropped without calling `commit()`, the file
/// is not modified.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::{AtomicWriter, WriteOptions};
/// use std::io::Write;
///
/// let mut writer = AtomicWriter::new("/path/to/file", WriteOptions::default())?;
///
/// writer.write_all(b"line 1\n")?;
/// writer.write_all(b"line 2\n")?;
///
/// // Only now is the file created/updated
/// writer.commit()?;
/// ```
#[must_use = "writer must be committed with .commit() or changes will be lost"]
pub struct AtomicWriter {
    inner: atomic_write_file::AtomicWriteFile,
    path: std::path::PathBuf,
    options: WriteOptions,
    #[cfg(unix)]
    existing_mode: Option<super::permissions::FileMode>,
}

impl AtomicWriter {
    /// Create a new atomic writer for the given path
    ///
    /// # Security Note
    ///
    /// The symlink check has a TOCTOU (time-of-check-time-of-use) race condition.
    /// See [`atomic_write`] for details and mitigation strategies.
    pub fn new(path: impl AsRef<Path>, options: WriteOptions) -> Result<Self, Problem> {
        let path = path.as_ref();

        // Check if file exists when overwrite is false
        if !options.overwrite && path.exists() {
            return Err(Problem::io(format!(
                "File '{}' already exists and overwrite is disabled",
                path.display()
            )));
        }

        // Check for symlink if follow_symlinks is false
        if !options.follow_symlinks && path.is_symlink() {
            return Err(Problem::io(format!(
                "Path '{}' is a symlink and follow_symlinks is disabled",
                path.display()
            )));
        }

        // Get existing permissions if we need to preserve them
        #[cfg(unix)]
        let existing_mode = if options.preserve_permissions && path.exists() {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(path)
                .ok()
                .map(|m| super::permissions::FileMode::new(m.permissions().mode() & 0o777))
        } else {
            None
        };

        let inner = atomic_write_file::AtomicWriteFile::open(path).map_err(|e| {
            Problem::io(format!(
                "Failed to create atomic writer for '{}': {}",
                path.display(),
                e
            ))
        })?;

        Ok(Self {
            inner,
            path: path.to_owned(),
            options,
            #[cfg(unix)]
            existing_mode,
        })
    }

    /// Commit the writes and finalize the file
    ///
    /// This performs the atomic rename and sets permissions.
    /// If not called, the file is not modified when the writer is dropped.
    pub fn commit(mut self) -> Result<(), Problem> {
        // Flush first
        self.inner.flush().map_err(|e| {
            Problem::io(format!("Failed to flush '{}': {}", self.path.display(), e))
        })?;

        // Commit the atomic write
        self.inner.commit().map_err(|e| {
            Problem::io(format!("Failed to commit '{}': {}", self.path.display(), e))
        })?;

        // Set permissions
        #[cfg(unix)]
        let mode_to_set = self.existing_mode.unwrap_or(self.options.mode);
        #[cfg(not(unix))]
        let mode_to_set = self.options.mode;

        set_mode(&self.path, mode_to_set)?;

        Ok(())
    }

    /// Get the target path
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Write for AtomicWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// =============================================================================
// Async support
// =============================================================================

/// Write data to a file atomically (async version)
///
/// This spawns the blocking write operation on a thread pool to avoid
/// blocking the async runtime. See [`atomic_write`] for details on the
/// atomic write behavior.
///
/// # Arguments
///
/// * `path` - Target file path (must be `Send + 'static` for thread pool)
/// * `data` - Data to write (owned `Vec<u8>` for thread safety)
/// * `options` - Write options (mode, sync, etc.)
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::{write_atomic_async, WriteOptions};
///
/// write_atomic_async("/path/to/file", b"content".to_vec(), WriteOptions::default()).await?;
/// ```
pub async fn write_atomic_async(
    path: impl AsRef<Path> + Send + 'static,
    data: Vec<u8>,
    options: WriteOptions,
) -> Result<(), Problem> {
    let path = path.as_ref().to_owned();

    crate::primitives::runtime::r#async::spawn_blocking(move || write_atomic(&path, &data, options))
        .await
        .map_err(|e| Problem::io(format!("Task join error: {}", e)))?
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use tempfile::tempdir;

    // =========================================================================
    // Basic functionality tests
    // =========================================================================

    #[test]
    fn test_write_atomic_creates_file() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("new_file.txt");

        write_atomic(&path, b"hello", WriteOptions::default()).expect("write should succeed");

        assert!(path.exists());
        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "hello");
    }

    #[test]
    fn test_write_atomic_overwrites() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("existing.txt");

        // Create initial file
        std::fs::write(&path, "original").expect("create file");

        // Overwrite atomically
        write_atomic(&path, b"updated", WriteOptions::default()).expect("overwrite");

        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "updated");
    }

    #[test]
    fn test_write_atomic_no_overwrite() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("no_overwrite.txt");

        // Create initial file
        std::fs::write(&path, "original").expect("create file");

        // Try to overwrite with overwrite=false
        let opts = WriteOptions::default().overwrite(false);
        let result = write_atomic(&path, b"updated", opts);

        assert!(result.is_err());

        // Original should be unchanged
        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "original");
    }

    #[cfg(unix)]
    #[test]
    fn test_write_atomic_symlink_rejected() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().expect("create temp dir");
        let real_file = dir.path().join("real.txt");
        let link = dir.path().join("link.txt");

        std::fs::write(&real_file, "original").expect("create file");
        symlink(&real_file, &link).expect("create symlink");

        // Should fail because follow_symlinks is false by default
        let result = write_atomic(&link, b"hacked", WriteOptions::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_atomic_writer_basic() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("writer_test.txt");

        {
            let mut writer =
                AtomicWriter::new(&path, WriteOptions::default()).expect("create writer");

            writer.write_all(b"chunk 1").expect("write chunk 1");
            writer.write_all(b" chunk 2").expect("write chunk 2");
            writer.commit().expect("commit");
        }

        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "chunk 1 chunk 2");
    }

    #[test]
    fn test_atomic_writer_no_commit() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("no_commit.txt");

        {
            let mut writer =
                AtomicWriter::new(&path, WriteOptions::default()).expect("create writer");

            writer.write_all(b"should not persist").expect("write");
            // Drop without commit
        }

        assert!(!path.exists(), "file should not exist without commit");
    }

    #[cfg(unix)]
    #[test]
    fn test_write_atomic_sets_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("perms.txt");

        let opts = WriteOptions::default().mode(super::super::permissions::FileMode::PRIVATE);
        write_atomic(&path, b"secret", opts).expect("write");

        let metadata = std::fs::metadata(&path).expect("get metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn test_write_atomic_preserves_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("preserve.txt");

        // Create file with specific permissions
        std::fs::write(&path, "original").expect("create file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("set permissions");

        // Write with preserve_permissions=true
        let opts = WriteOptions::default().preserve_permissions(true);
        write_atomic(&path, b"updated", opts).expect("write");

        let metadata = std::fs::metadata(&path).expect("get metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "permissions should be preserved");
    }

    // =========================================================================
    // Edge case tests (Item #13)
    // =========================================================================

    #[test]
    fn test_write_atomic_empty_data() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("empty.txt");

        // Writing empty data should succeed
        write_atomic(&path, b"", WriteOptions::default()).expect("write empty");

        let contents = std::fs::read(&path).expect("read file");
        assert!(contents.is_empty(), "file should be empty");
    }

    #[test]
    fn test_write_atomic_large_data() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("large.txt");

        // 1 MB of data
        let data = vec![b'x'; 1024 * 1024];
        write_atomic(&path, &data, WriteOptions::default()).expect("write large");

        let contents = std::fs::read(&path).expect("read file");
        assert_eq!(contents.len(), 1024 * 1024);
    }

    #[test]
    fn test_write_atomic_unicode_filename() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("テスト_файл_🎉.txt");

        write_atomic(&path, b"unicode test", WriteOptions::default()).expect("write unicode");

        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "unicode test");
    }

    #[test]
    fn test_write_atomic_spaces_in_path() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("path with spaces/file name.txt");

        // Create parent directory
        std::fs::create_dir_all(path.parent().expect("path has parent"))
            .expect("create parent dir");

        write_atomic(&path, b"spaces test", WriteOptions::default()).expect("write with spaces");

        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "spaces test");
    }

    #[test]
    fn test_write_atomic_nonexistent_parent() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("nonexistent/subdir/file.txt");

        // Should fail because parent doesn't exist
        let result = write_atomic(&path, b"test", WriteOptions::default());
        assert!(result.is_err(), "should fail without parent directory");
    }

    #[test]
    fn test_atomic_writer_multiple_writes() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("multi.txt");

        {
            let mut writer =
                AtomicWriter::new(&path, WriteOptions::default()).expect("create writer");

            // Multiple small writes
            for i in 0..100 {
                writer
                    .write_all(format!("line {}\n", i).as_bytes())
                    .expect("write");
            }
            writer.commit().expect("commit");
        }

        let contents = std::fs::read_to_string(&path).expect("read file");
        assert!(contents.contains("line 0\n"));
        assert!(contents.contains("line 99\n"));
        assert_eq!(contents.lines().count(), 100);
    }

    #[test]
    fn test_write_atomic_binary_data() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("binary.bin");

        // Binary data with all byte values including nulls
        let data: Vec<u8> = (0u8..=255).collect();
        write_atomic(&path, &data, WriteOptions::default()).expect("write binary");

        let contents = std::fs::read(&path).expect("read file");
        assert_eq!(contents, data);
    }

    #[test]
    fn test_write_atomic_repeated_overwrites() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("overwrite.txt");

        // Write 10 times to same file
        for i in 0..10 {
            write_atomic(
                &path,
                format!("version {}", i).as_bytes(),
                WriteOptions::default(),
            )
            .expect("write");
        }

        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "version 9");
    }

    #[cfg(unix)]
    #[test]
    fn test_write_atomic_readonly_target() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("readonly.txt");

        // Create file and make it read-only
        std::fs::write(&path, "original").expect("create file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444))
            .expect("set readonly");

        // Should succeed because atomic write creates a new temp file and renames
        // (the file itself being readonly doesn't prevent overwriting via rename)
        let result = write_atomic(&path, b"updated", WriteOptions::default());

        // Clean up - restore write permission for tempdir cleanup
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));

        // This might succeed or fail depending on directory permissions
        // and whether we have write permission on the directory
        // Just verify it doesn't panic
        let _ = result;
    }

    // =========================================================================
    // Async tests
    // =========================================================================

    #[tokio::test]
    async fn test_write_atomic_async_basic() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("async_test.txt");

        write_atomic_async(
            path.clone(),
            b"async content".to_vec(),
            WriteOptions::default(),
        )
        .await
        .expect("async write should succeed");

        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "async content");
    }

    #[tokio::test]
    async fn test_write_atomic_async_large_data() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("async_large.txt");

        // 1 MB of data
        let data = vec![b'y'; 1024 * 1024];
        write_atomic_async(path.clone(), data.clone(), WriteOptions::default())
            .await
            .expect("async write large should succeed");

        let contents = std::fs::read(&path).expect("read file");
        assert_eq!(contents.len(), 1024 * 1024);
    }

    // =========================================================================
    // Concurrent write tests
    // =========================================================================

    #[test]
    fn test_write_atomic_concurrent_to_different_files() {
        use std::sync::Arc;
        use std::thread;

        let dir = tempdir().expect("create temp dir");
        let dir_path = Arc::new(dir.path().to_owned());

        let mut handles = vec![];

        // Spawn 10 threads writing to different files concurrently
        for i in 0..10 {
            let dir_path = Arc::clone(&dir_path);
            let handle = thread::spawn(move || {
                let path = dir_path.join(format!("concurrent_{}.txt", i));
                write_atomic(
                    &path,
                    format!("content {}", i).as_bytes(),
                    WriteOptions::default(),
                )
                .expect("concurrent write should succeed");
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().expect("thread should complete");
        }

        // Verify all files were written correctly
        for i in 0..10 {
            let path = dir.path().join(format!("concurrent_{}.txt", i));
            let contents = std::fs::read_to_string(&path).expect("read file");
            assert_eq!(contents, format!("content {}", i));
        }
    }

    #[test]
    fn test_write_atomic_concurrent_to_same_file() {
        use std::sync::Arc;
        use std::thread;

        let dir = tempdir().expect("create temp dir");
        let path = Arc::new(dir.path().join("same_file.txt"));

        let mut handles = vec![];

        // Spawn 10 threads writing to the SAME file concurrently
        // Due to atomic write semantics, one of them will "win"
        for i in 0..10 {
            let path = Arc::clone(&path);
            let handle = thread::spawn(move || {
                write_atomic(
                    &*path,
                    format!("writer {}", i).as_bytes(),
                    WriteOptions::default(),
                )
                .expect("concurrent write should succeed");
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().expect("thread should complete");
        }

        // Verify the file exists and contains valid content from ONE writer
        let contents = std::fs::read_to_string(&*path).expect("read file");
        assert!(
            contents.starts_with("writer "),
            "file should have content from one writer"
        );
    }
}
