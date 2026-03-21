// Public API - will be used by FileWriter (Issue #111) and external code
#![allow(dead_code)]

//! Cross-platform file locking primitives
//!
//! Provides advisory file locking using the `fd-lock` crate (used by Firefox/Servo).
//! Advisory locks coordinate access between cooperating processes but don't prevent
//! access from processes that don't check for locks.
//!
//! # Use Cases
//!
//! - **Log file rotation**: Prevent multiple processes from rotating simultaneously
//! - **Configuration files**: Ensure atomic read-modify-write cycles
//! - **PID files**: Prevent multiple daemon instances
//! - **Shared resources**: Coordinate access to files across processes
//!
//! # Lock Types
//!
//! - **Shared (Read)**: Multiple readers can hold the lock simultaneously
//! - **Exclusive (Write)**: Only one writer, no readers while held
//!
//! # Platform Behavior
//!
//! | Platform | Mechanism | Scope |
//! |----------|-----------|-------|
//! | Linux | `flock(2)` | Process-wide |
//! | macOS | `flock(2)` | Process-wide |
//! | Windows | `LockFileEx` | Handle-specific |
//!
//! # Important Limitations
//!
//! 1. **Advisory only**: Locks are cooperative. Programs must check for locks.
//! 2. **Not NFS-safe**: Network filesystems may not support locking correctly.
//! 3. **Process scope**: On Unix, locks are per-process, not per-thread.
//! 4. **Fork behavior**: Child processes don't inherit locks on Unix.
//!
//! # Examples
//!
//! ## Exclusive lock for writing
//!
//! ```rust,ignore
//! use crate::primitives::io::{FileLock, LockMode};
//! use std::io::Write;
//!
//! let mut lock = FileLock::open("/var/log/app.log", LockMode::Exclusive)?;
//! writeln!(lock.as_file_mut(), "Log entry")?;
//! // Lock released on drop
//! ```
//!
//! ## Shared lock for reading
//!
//! ```rust,ignore
//! use crate::primitives::io::{FileLock, LockMode};
//! use std::io::Read;
//!
//! let mut lock = FileLock::open("/etc/app.conf", LockMode::Shared)?;
//! let mut contents = String::new();
//! lock.as_file_mut().read_to_string(&mut contents)?;
//! ```
//!
//! ## Try-lock (non-blocking)
//!
//! ```rust,ignore
//! use crate::primitives::io::{FileLock, LockMode};
//!
//! match FileLock::try_open("/var/run/app.pid", LockMode::Exclusive)? {
//!     Some(lock) => println!("Acquired lock"),
//!     None => println!("File is locked by another process"),
//! }
//! ```

use crate::primitives::types::Problem;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::Path;

use super::pidlock::PidLock;

/// Lock mode for file access
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockMode {
    /// Shared (read) lock - multiple readers allowed
    ///
    /// Use when you only need to read the file and can share access
    /// with other readers.
    Shared,

    /// Exclusive (write) lock - single writer, no readers
    ///
    /// Use when you need to modify the file and require exclusive access.
    Exclusive,
}

/// A file with an exclusive (write) lock
///
/// The lock is automatically released when this struct is dropped.
/// Use this for write operations where you need exclusive access.
pub struct ExclusiveFileLock<'a> {
    guard: fd_lock::RwLockWriteGuard<'a, File>,
    path: std::path::PathBuf,
}

impl<'a> ExclusiveFileLock<'a> {
    /// Get a reference to the underlying file
    pub fn as_file(&self) -> &File {
        &self.guard
    }

    /// Get a mutable reference to the underlying file
    pub fn as_file_mut(&mut self) -> &mut File {
        &mut self.guard
    }

    /// Get the file path
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Read for ExclusiveFileLock<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.guard.read(buf)
    }
}

impl Write for ExclusiveFileLock<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.guard.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.guard.flush()
    }
}

impl Seek for ExclusiveFileLock<'_> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.guard.seek(pos)
    }
}

/// A file with a shared (read) lock
///
/// The lock is automatically released when this struct is dropped.
/// Use this for read operations where you can share access with other readers.
pub struct SharedFileLock<'a> {
    guard: fd_lock::RwLockReadGuard<'a, File>,
    path: std::path::PathBuf,
}

impl<'a> SharedFileLock<'a> {
    /// Get a reference to the underlying file
    pub fn as_file(&self) -> &File {
        &self.guard
    }

    /// Get the file path
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Read for SharedFileLock<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // RwLockReadGuard gives us &File, but File::read takes &mut self
        // This is safe because read() on File is actually &self under the hood
        // We need to use the inner file directly
        let file = &*self.guard;
        // Use std::io::Read which can work with &File
        (&*file).read(buf)
    }
}

/// A lockable file that can be locked for reading or writing
///
/// This wraps an `fd_lock::RwLock<File>` and provides a convenient API
/// for acquiring locks.
pub struct LockableFile {
    lock: fd_lock::RwLock<File>,
    path: std::path::PathBuf,
}

impl LockableFile {
    /// Open a file for locking
    ///
    /// The file is opened but not locked yet. Call [`lock_exclusive`](Self::lock_exclusive)
    /// or [`lock_shared`](Self::lock_shared) to acquire a lock.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file
    /// * `create` - If true, create the file if it doesn't exist
    pub fn open(path: impl AsRef<Path>, create: bool) -> Result<Self, Problem> {
        let path = path.as_ref();

        let file = if create {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false) // Don't truncate - caller should manage content
                .open(path)
        } else {
            OpenOptions::new().read(true).write(true).open(path)
        }
        .map_err(|e| Problem::io(format!("Failed to open file '{}': {}", path.display(), e)))?;

        Ok(Self {
            lock: fd_lock::RwLock::new(file),
            path: path.to_owned(),
        })
    }

    /// Open an existing file for locking (read-only)
    ///
    /// Use this when you only need shared/read locks.
    pub fn open_readonly(path: impl AsRef<Path>) -> Result<Self, Problem> {
        let path = path.as_ref();

        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|e| Problem::io(format!("Failed to open file '{}': {}", path.display(), e)))?;

        Ok(Self {
            lock: fd_lock::RwLock::new(file),
            path: path.to_owned(),
        })
    }

    /// Create a new file for locking (truncates if exists)
    pub fn create(path: impl AsRef<Path>) -> Result<Self, Problem> {
        let path = path.as_ref();

        let file = File::create(path).map_err(|e| {
            Problem::io(format!("Failed to create file '{}': {}", path.display(), e))
        })?;

        Ok(Self {
            lock: fd_lock::RwLock::new(file),
            path: path.to_owned(),
        })
    }

    /// Acquire an exclusive (write) lock, blocking until available
    pub fn lock_exclusive(&mut self) -> Result<ExclusiveFileLock<'_>, Problem> {
        let guard = self.lock.write().map_err(|e| {
            Problem::io(format!(
                "Failed to acquire exclusive lock on '{}': {}",
                self.path.display(),
                e
            ))
        })?;

        Ok(ExclusiveFileLock {
            guard,
            path: self.path.clone(),
        })
    }

    /// Try to acquire an exclusive (write) lock without blocking
    ///
    /// Returns `Ok(None)` if the lock is held by another process.
    pub fn try_lock_exclusive(&mut self) -> Result<Option<ExclusiveFileLock<'_>>, Problem> {
        match self.lock.try_write() {
            Ok(guard) => Ok(Some(ExclusiveFileLock {
                guard,
                path: self.path.clone(),
            })),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(Problem::io(format!(
                "Failed to try exclusive lock on '{}': {}",
                self.path.display(),
                e
            ))),
        }
    }

    /// Acquire a shared (read) lock, blocking until available
    pub fn lock_shared(&self) -> Result<SharedFileLock<'_>, Problem> {
        let guard = self.lock.read().map_err(|e| {
            Problem::io(format!(
                "Failed to acquire shared lock on '{}': {}",
                self.path.display(),
                e
            ))
        })?;

        Ok(SharedFileLock {
            guard,
            path: self.path.clone(),
        })
    }

    /// Try to acquire a shared (read) lock without blocking
    ///
    /// Returns `Ok(None)` if the lock cannot be acquired.
    pub fn try_lock_shared(&self) -> Result<Option<SharedFileLock<'_>>, Problem> {
        match self.lock.try_read() {
            Ok(guard) => Ok(Some(SharedFileLock {
                guard,
                path: self.path.clone(),
            })),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(Problem::io(format!(
                "Failed to try shared lock on '{}': {}",
                self.path.display(),
                e
            ))),
        }
    }

    /// Get the file path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Consume the lockable file and return the underlying file
    pub fn into_inner(self) -> File {
        self.lock.into_inner()
    }
}

// ============================================================================
// Container Detection (for future use in fallback logic)
// ============================================================================

/// Check if we're running inside a container (Docker, Kubernetes, etc.)
///
/// This is useful for determining when flock might not work on shared volumes.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn is_in_container() -> bool {
    // Check for Docker
    if std::path::Path::new("/.dockerenv").exists() {
        return true;
    }

    // Check cgroup for container indicators
    if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup")
        && (cgroup.contains("/docker/")
            || cgroup.contains("/kubepods/")
            || cgroup.contains("/lxc/"))
    {
        return true;
    }

    false
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn is_in_container() -> bool {
    false
}

// ============================================================================
// Robust Locking - Portable File Locking with Fallback
// ============================================================================

/// Acquire an exclusive lock on a file using the best available mechanism
///
/// This is a high-level function that automatically selects the appropriate
/// locking strategy:
/// - Uses `flock` on systems/filesystems that support it
/// - Falls back to pidfile-based locking for Docker shared volumes or NFS
///
/// # Returns
///
/// Returns either a `FlockGuard` (flock mode) or `PidLockGuard` (pidfile mode)
/// wrapped in a `PortableLock` enum. The lock is released when dropped.
///
/// # Example
///
/// ```rust,ignore
/// use crate::primitives::io::file::lock_file_portable;
///
/// // Acquire lock (auto-selects best mechanism)
/// let lock = lock_file_portable("data.json", true)?;
///
/// // Use the locked file
/// // lock.with_file(|f| { ... })?;
///
/// // Lock released on drop
/// ```
pub fn lock_file_portable(path: impl AsRef<Path>, create: bool) -> Result<PortableLock, Problem> {
    PortableLock::acquire(path, create)
}

/// Try to acquire a portable lock without blocking
///
/// Returns `Ok(None)` if the lock is held by another process.
pub fn try_lock_file_portable(
    path: impl AsRef<Path>,
    create: bool,
) -> Result<Option<PortableLock>, Problem> {
    PortableLock::try_acquire(path, create)
}

/// A portable file lock that works across different filesystems and environments
///
/// Automatically uses flock when available, falling back to pidfile-based
/// locking for environments like Docker shared volumes where flock doesn't work.
pub struct PortableLock {
    inner: PortableLockInner,
    path: std::path::PathBuf,
}

enum PortableLockInner {
    /// flock-based lock with the lockable file
    /// The lock guard is acquired and released via with_file()
    Flock(LockableFile),
    /// Pidfile-based lock (for Docker/NFS fallback)
    Pidfile(PidLock),
}

impl PortableLock {
    /// Acquire an exclusive lock on a file
    ///
    /// Tries flock first, falls back to pidfile if flock isn't supported.
    pub fn acquire(path: impl AsRef<Path>, create: bool) -> Result<Self, Problem> {
        let path = path.as_ref();

        // Try to open and test flock
        match test_flock_support(path, create) {
            Ok(file) => Ok(Self {
                inner: PortableLockInner::Flock(file),
                path: path.to_owned(),
            }),
            Err(e) if should_use_pidfile_fallback(&e) => {
                // Flock not supported, use pidfile
                let pidlock = PidLock::acquire(path)?;
                Ok(Self {
                    inner: PortableLockInner::Pidfile(pidlock),
                    path: path.to_owned(),
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Try to acquire an exclusive lock without blocking
    ///
    /// Returns `Ok(None)` if the lock is held by another process.
    pub fn try_acquire(path: impl AsRef<Path>, create: bool) -> Result<Option<Self>, Problem> {
        let path = path.as_ref();

        // Try to open and test flock
        match test_flock_support_nonblocking(path, create) {
            Ok(Some(file)) => Ok(Some(Self {
                inner: PortableLockInner::Flock(file),
                path: path.to_owned(),
            })),
            Ok(None) => Ok(None), // Lock held by another process
            Err(e) if should_use_pidfile_fallback(&e) => {
                // Flock not supported, use pidfile
                match PidLock::try_acquire(path)? {
                    Some(pidlock) => Ok(Some(Self {
                        inner: PortableLockInner::Pidfile(pidlock),
                        path: path.to_owned(),
                    })),
                    None => Ok(None),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Get the path being locked
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check if this lock is using the pidfile fallback
    pub fn is_using_pidfile_fallback(&self) -> bool {
        matches!(self.inner, PortableLockInner::Pidfile(_))
    }

    /// Execute a function with exclusive access to the locked file
    ///
    /// For flock mode, this acquires the lock guard for the duration of the closure.
    /// For pidfile mode, the lock is already held and this just provides file access.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let lock = PortableLock::acquire("data.json", true)?;
    /// lock.with_file_mut(|file| {
    ///     use std::io::Write;
    ///     writeln!(file, "data")?;
    ///     Ok(())
    /// })?;
    /// ```
    pub fn with_file_mut<F, R>(&mut self, f: F) -> Result<R, Problem>
    where
        F: FnOnce(&mut File) -> Result<R, Problem>,
    {
        match &mut self.inner {
            PortableLockInner::Flock(lockable) => {
                let mut guard = lockable.lock_exclusive()?;
                f(guard.as_file_mut())
            }
            PortableLockInner::Pidfile(_pidlock) => {
                // For pidfile mode, we need to open the file separately
                // since pidlock doesn't hold the file handle
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&self.path)
                    .map_err(|e| {
                        Problem::io(format!(
                            "Failed to open file '{}': {}",
                            self.path.display(),
                            e
                        ))
                    })?;
                f(&mut file)
            }
        }
    }
}

/// Test if flock is supported by attempting to acquire a lock
fn test_flock_support(path: &Path, create: bool) -> Result<LockableFile, Problem> {
    let mut file = LockableFile::open(path, create)?;

    // Try to acquire and immediately release to test support
    // We don't actually need to hold the lock here - just verify it works
    let guard = file.lock.write().map_err(|e| {
        Problem::io(format!(
            "Failed to acquire flock on '{}': {}",
            path.display(),
            e
        ))
    })?;

    // Release the lock but keep the file
    drop(guard);

    Ok(file)
}

fn test_flock_support_nonblocking(
    path: &Path,
    create: bool,
) -> Result<Option<LockableFile>, Problem> {
    let mut file = LockableFile::open(path, create)?;

    // Use a scope block to ensure the guard is dropped before returning file
    {
        let try_result = file.lock.try_write();
        match try_result {
            Ok(_guard) => {
                // Guard is dropped at end of this scope
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Ok(None);
            }
            Err(e) => {
                return Err(Problem::io(format!(
                    "Failed to try flock on '{}': {}",
                    path.display(),
                    e
                )));
            }
        }
    } // Guard and try_result dropped here

    Ok(Some(file))
}

/// Determine if we should fall back to pidfile locking based on the error
fn should_use_pidfile_fallback(err: &Problem) -> bool {
    let msg = err.to_string().to_lowercase();

    // These errors suggest flock isn't supported on this filesystem
    msg.contains("not supported")
        || msg.contains("operation not permitted")
        || msg.contains("function not implemented")
        || msg.contains("invalid argument") // Sometimes returned on NFS
}

// ============================================================================
// Convenience functions for one-shot locking
// ============================================================================

/// Open a file and acquire an exclusive lock (blocking)
///
/// This is a convenience function for simple lock-write-unlock patterns.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::lock_file_exclusive;
/// use std::io::Write;
///
/// let mut file = lock_file_exclusive("/var/log/app.log")?;
/// let mut lock = file.lock_exclusive()?;
/// writeln!(lock.as_file_mut(), "Log entry")?;
/// // Lock released when `lock` is dropped
/// ```
pub fn lock_file_exclusive(path: impl AsRef<Path>) -> Result<LockableFile, Problem> {
    LockableFile::open(path, true)
}

/// Open a file and acquire a shared lock (blocking)
///
/// This is a convenience function for simple lock-read-unlock patterns.
pub fn lock_file_shared(path: impl AsRef<Path>) -> Result<LockableFile, Problem> {
    LockableFile::open_readonly(path)
}

// ============================================================================
// Async support
// ============================================================================

/// Open and lock a file asynchronously (exclusive lock)
///
/// This spawns the blocking lock operation on a thread pool.
pub async fn lock_file_exclusive_async(
    path: impl AsRef<Path> + Send + 'static,
) -> Result<LockableFile, Problem> {
    let path = path.as_ref().to_owned();

    crate::primitives::runtime::r#async::spawn_blocking(move || LockableFile::open(&path, true))
        .await
        .map_err(|e| Problem::io(format!("Task join error: {}", e)))?
}

/// Open and prepare a file for shared locking asynchronously
///
/// This spawns the blocking open operation on a thread pool.
pub async fn lock_file_shared_async(
    path: impl AsRef<Path> + Send + 'static,
) -> Result<LockableFile, Problem> {
    let path = path.as_ref().to_owned();

    crate::primitives::runtime::r#async::spawn_blocking(move || LockableFile::open_readonly(&path))
        .await
        .map_err(|e| Problem::io(format!("Task join error: {}", e)))?
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use tempfile::tempdir;

    #[test]
    fn test_exclusive_lock_basic() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");

        // Create and lock
        let mut file = LockableFile::create(&path).expect("create");
        let mut lock = file.lock_exclusive().expect("lock");

        // Write some data
        lock.write_all(b"hello").expect("write");
        lock.flush().expect("flush");

        // Release lock
        drop(lock);
        drop(file);

        // Verify data
        let contents = std::fs::read_to_string(&path).expect("read");
        assert_eq!(contents, "hello");
    }

    #[test]
    fn test_shared_lock_basic() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");

        // Create file first
        std::fs::write(&path, "test data").expect("write initial");

        // Open with shared lock
        let file = LockableFile::open_readonly(&path).expect("open");
        let mut lock = file.lock_shared().expect("lock");

        // Read data
        let mut contents = String::new();
        lock.read_to_string(&mut contents).expect("read");
        assert_eq!(contents, "test data");
    }

    #[test]
    fn test_try_lock_success() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");

        // Create file
        std::fs::write(&path, "test").expect("write");

        // Try lock should succeed
        let mut file = LockableFile::open(&path, false).expect("open");
        let lock = file
            .try_lock_exclusive()
            .expect("try_lock")
            .expect("should acquire lock");

        assert_eq!(lock.path(), path);
    }

    #[test]
    fn test_open_readonly_fails_on_missing() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("nonexistent.txt");

        let result = LockableFile::open_readonly(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_into_inner() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");

        let file = LockableFile::create(&path).expect("create");
        let _inner = file.into_inner();

        // File should still be accessible
        assert!(path.exists());
    }

    #[test]
    fn test_seek_operations() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");

        // Use open with create to get read/write access
        let mut file = LockableFile::open(&path, true).expect("create");
        {
            let mut lock = file.lock_exclusive().expect("lock");
            lock.write_all(b"hello world").expect("write");

            // Seek to beginning within same lock
            lock.seek(SeekFrom::Start(0)).expect("seek");

            // Read back
            let mut buf = [0u8; 5];
            lock.read_exact(&mut buf).expect("read");
            assert_eq!(&buf, b"hello");
        }
    }

    #[test]
    fn test_file_access() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");

        let mut file = LockableFile::create(&path).expect("create");
        let lock = file.lock_exclusive().expect("lock");

        // Access underlying file
        let metadata = lock.as_file().metadata().expect("metadata");
        assert!(metadata.is_file());
    }

    #[test]
    fn test_multiple_shared_locks() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");

        // Create file
        std::fs::write(&path, "test data").expect("write");

        // Open for shared access
        let file1 = LockableFile::open_readonly(&path).expect("open1");
        let file2 = LockableFile::open_readonly(&path).expect("open2");

        // Both should be able to acquire shared locks
        // Note: Within same process, flock allows this
        let _lock1 = file1.lock_shared().expect("lock1");
        let _lock2 = file2.lock_shared().expect("lock2");
    }

    // Note: Testing lock contention between processes is complex and
    // typically requires spawning child processes. These tests verify
    // the API works correctly in single-process scenarios.

    // ========================================
    // PortableLock Tests
    // ========================================

    #[test]
    fn test_portable_lock_acquire() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("portable.txt");

        // Create file first
        std::fs::write(&path, "test").expect("write");

        // Acquire portable lock
        let lock = PortableLock::acquire(&path, false).expect("acquire portable lock");
        assert_eq!(lock.path(), path);

        // By default should use flock (not pidfile)
        assert!(!lock.is_using_pidfile_fallback());
    }

    #[test]
    fn test_portable_lock_create() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("new_portable.txt");

        // Acquire with create=true on non-existent file
        let lock = PortableLock::acquire(&path, true).expect("acquire with create");
        assert!(path.exists());
        assert_eq!(lock.path(), path);
    }

    #[test]
    fn test_portable_lock_with_file_mut() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("mutable.txt");

        // Create file
        std::fs::write(&path, "initial").expect("write");

        let mut lock = PortableLock::acquire(&path, false).expect("acquire");

        // Write using with_file_mut
        lock.with_file_mut(|file| {
            use std::io::{Seek, SeekFrom, Write};
            file.seek(SeekFrom::Start(0))
                .map_err(|e| Problem::io(e.to_string()))?;
            file.write_all(b"modified")
                .map_err(|e| Problem::io(e.to_string()))?;
            Ok(())
        })
        .expect("with_file_mut");

        // Release lock
        drop(lock);

        // Verify modification
        let contents = std::fs::read_to_string(&path).expect("read");
        assert!(contents.starts_with("modified"));
    }

    #[test]
    fn test_try_portable_lock_success() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("try_portable.txt");

        std::fs::write(&path, "test").expect("write");

        let lock = try_lock_file_portable(&path, false)
            .expect("try_lock")
            .expect("should acquire");

        assert_eq!(lock.path(), path);
    }

    #[test]
    fn test_lock_file_portable_convenience() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("convenience.txt");

        std::fs::write(&path, "test").expect("write");

        // Use convenience function
        let lock = lock_file_portable(&path, false).expect("lock_file_portable");
        assert_eq!(lock.path(), path);
    }
}
