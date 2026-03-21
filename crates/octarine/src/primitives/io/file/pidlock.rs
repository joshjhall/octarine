//! Pidfile-based locking for environments where flock doesn't work
//!
//! This module provides a fallback locking mechanism using pidfiles.
//! It's designed for Docker containers where flock may not work on shared volumes.
//!
//! # How It Works
//!
//! 1. Create a `.lock` file alongside the target file
//! 2. Write the current PID to the lock file
//! 3. Use atomic file creation (O_EXCL) to ensure exclusivity
//! 4. Detect and clean up stale locks from dead processes
//!
//! # Limitations
//!
//! - Only supports exclusive locks (no shared locks)
//! - Relies on PID checking which has race condition potential
//! - Stale lock detection only works within same PID namespace

// Public API - used by locking module for fallback
#![allow(dead_code)]

use crate::primitives::types::Problem;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process;

/// A pidfile-based lock
///
/// Creates a `.lock` file containing the current process ID.
/// The lock is released when this struct is dropped.
pub struct PidLock {
    lock_path: PathBuf,
    target_path: PathBuf,
}

impl PidLock {
    /// Attempt to acquire a pidfile lock
    ///
    /// Creates a lock file at `{path}.lock` containing the current PID.
    /// If a lock file exists but the process is dead, the stale lock is cleaned up.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The lock is held by another live process
    /// - The lock file cannot be created
    pub fn acquire(path: impl AsRef<Path>) -> Result<Self, Problem> {
        let path = path.as_ref();
        let lock_path = lock_path_for(path);
        let pid = process::id();

        // Try to create lock file exclusively
        match create_lock_exclusive(&lock_path, pid) {
            Ok(()) => {
                return Ok(Self {
                    lock_path,
                    target_path: path.to_owned(),
                });
            }
            Err(e) if is_already_exists(&e) => {
                // Lock file exists - check if stale
            }
            Err(e) => {
                return Err(Problem::io(format!(
                    "Failed to create lock file '{}': {}",
                    lock_path.display(),
                    e
                )));
            }
        }

        // Lock file exists - check if stale
        if is_lock_stale(&lock_path)? {
            // Remove stale lock and try again
            std::fs::remove_file(&lock_path).map_err(|e| {
                Problem::io(format!(
                    "Failed to remove stale lock '{}': {}",
                    lock_path.display(),
                    e
                ))
            })?;

            // Try again
            create_lock_exclusive(&lock_path, pid).map_err(|e| {
                Problem::io(format!(
                    "Failed to create lock file '{}': {}",
                    lock_path.display(),
                    e
                ))
            })?;

            return Ok(Self {
                lock_path,
                target_path: path.to_owned(),
            });
        }

        // Lock is held by live process
        let holder_pid = read_lock_pid(&lock_path).unwrap_or(0);
        Err(Problem::io(format!(
            "Lock '{}' is held by process {}",
            lock_path.display(),
            holder_pid
        )))
    }

    /// Try to acquire a pidfile lock without blocking
    ///
    /// Returns `Ok(None)` if the lock is held by another process.
    pub fn try_acquire(path: impl AsRef<Path>) -> Result<Option<Self>, Problem> {
        let path = path.as_ref();
        let lock_path = lock_path_for(path);
        let pid = process::id();

        // Try to create lock file exclusively
        match create_lock_exclusive(&lock_path, pid) {
            Ok(()) => {
                return Ok(Some(Self {
                    lock_path,
                    target_path: path.to_owned(),
                }));
            }
            Err(e) if is_already_exists(&e) => {
                // Lock file exists - check if stale
            }
            Err(e) => {
                return Err(Problem::io(format!(
                    "Failed to create lock file '{}': {}",
                    lock_path.display(),
                    e
                )));
            }
        }

        // Lock file exists - check if stale
        if is_lock_stale(&lock_path)? {
            // Remove stale lock and try again
            if std::fs::remove_file(&lock_path).is_ok()
                && create_lock_exclusive(&lock_path, pid).is_ok()
            {
                return Ok(Some(Self {
                    lock_path,
                    target_path: path.to_owned(),
                }));
            }
        }

        // Lock is held
        Ok(None)
    }

    /// Get the path being locked
    pub fn target_path(&self) -> &Path {
        &self.target_path
    }

    /// Get the lock file path
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }
}

impl Drop for PidLock {
    fn drop(&mut self) {
        // Best-effort cleanup
        let _ = std::fs::remove_file(&self.lock_path);
    }
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Get the lock file path for a given target path
fn lock_path_for(path: &Path) -> PathBuf {
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

/// Create a lock file exclusively with the given PID
fn create_lock_exclusive(lock_path: &Path, pid: u32) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true) // O_EXCL - fail if exists
        .open(lock_path)?;

    write!(file, "{}", pid)?;
    file.sync_all()?;
    Ok(())
}

/// Check if an IO error indicates the file already exists
fn is_already_exists(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::AlreadyExists
}

/// Read the PID from a lock file
fn read_lock_pid(lock_path: &Path) -> Option<u32> {
    let mut file = File::open(lock_path).ok()?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).ok()?;
    contents.trim().parse().ok()
}

/// Check if a lock is stale (holder process is dead)
fn is_lock_stale(lock_path: &Path) -> Result<bool, Problem> {
    let pid = match read_lock_pid(lock_path) {
        Some(pid) => pid,
        None => {
            // Can't read PID - assume stale (corrupted lock file)
            return Ok(true);
        }
    };

    // Check if process exists
    Ok(!is_process_alive(pid))
}

/// Check if a process is still running
///
/// Uses /proc filesystem on Linux, which is safe and doesn't require unsafe code.
#[cfg(target_os = "linux")]
fn is_process_alive(pid: u32) -> bool {
    // On Linux, check if /proc/{pid} exists
    Path::new(&format!("/proc/{}", pid)).exists()
}

/// Check if a process is still running on macOS
///
/// Uses ps command since macOS doesn't have /proc.
#[cfg(target_os = "macos")]
fn is_process_alive(pid: u32) -> bool {
    // Use ps to check if process exists
    std::process::Command::new("ps")
        .args(["-p", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Check if a process is still running on Windows
#[cfg(target_os = "windows")]
fn is_process_alive(pid: u32) -> bool {
    // Use tasklist to check if process exists
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid)])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
        .unwrap_or(false)
}

// Fallback for other platforms
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn is_process_alive(_pid: u32) -> bool {
    // Can't check - assume alive to be safe
    true
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_acquire_and_release() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");

        // Create the target file
        std::fs::write(&path, "test").expect("write file");

        // Acquire lock
        let lock = PidLock::acquire(&path).expect("acquire lock");
        assert!(lock.lock_path().exists());

        // Release lock
        drop(lock);
        assert!(!lock_path_for(&path).exists());
    }

    #[test]
    fn test_try_acquire_success() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");

        std::fs::write(&path, "test").expect("write file");

        let lock = PidLock::try_acquire(&path)
            .expect("try_acquire")
            .expect("should get lock");

        assert_eq!(lock.target_path(), path);
    }

    #[test]
    fn test_try_acquire_contention() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");

        std::fs::write(&path, "test").expect("write file");

        // Acquire first lock
        let _lock1 = PidLock::acquire(&path).expect("first lock");

        // Second lock should fail
        let lock2 = PidLock::try_acquire(&path).expect("try_acquire");
        assert!(lock2.is_none());
    }

    #[test]
    fn test_stale_lock_cleanup() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");
        let lock_path = lock_path_for(&path);

        std::fs::write(&path, "test").expect("write file");

        // Create a fake stale lock with PID 1 (init, unlikely to be us)
        // Actually use PID 99999999 which almost certainly doesn't exist
        std::fs::write(&lock_path, "99999999").expect("write stale lock");

        // Should be able to acquire despite existing lock file
        let lock = PidLock::acquire(&path).expect("acquire over stale");
        assert!(lock.lock_path().exists());

        // Verify our PID is now in the lock
        let contents = std::fs::read_to_string(&lock_path).expect("read lock");
        assert_eq!(contents, process::id().to_string());
    }

    #[test]
    fn test_lock_path_generation() {
        let path = Path::new("/tmp/test.txt");
        let lock = lock_path_for(path);
        assert_eq!(lock, PathBuf::from("/tmp/test.txt.lock"));
    }

    #[test]
    fn test_current_process_alive() {
        assert!(is_process_alive(process::id()));
    }

    #[test]
    fn test_nonexistent_process_dead() {
        // PID 99999999 almost certainly doesn't exist
        assert!(!is_process_alive(99_999_999));
    }
}
