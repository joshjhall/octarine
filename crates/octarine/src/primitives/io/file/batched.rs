//! Batched writer for high-frequency write scenarios
//!
//! Provides buffered writing that accumulates writes and flushes periodically,
//! reducing the overhead of per-write atomic operations.
//!
//! ## Use Cases
//!
//! - **Log files**: Buffer log entries, flush periodically
//! - **Metrics collection**: Accumulate metrics, batch commit
//! - **Audit trails**: Buffer events, atomic batch writes
//!
//! ## Design Philosophy
//!
//! - **Memory-bounded**: Configurable max buffer size
//! - **Time-bounded**: Configurable flush interval
//! - **Atomic commits**: Each flush is an atomic operation
//! - **Best-effort on drop**: Attempts flush when dropped

// Public API - will be used by FileWriter (Issue #111) and external code
#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::atomic::AtomicWriter;
use super::options::WriteOptions;
use crate::primitives::types::Problem;

/// Default maximum buffer size (64 KB)
const DEFAULT_MAX_BUFFER_SIZE: usize = 64 * 1024;

/// Default flush interval (1 second)
const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(1);

/// Batched writer that accumulates writes and flushes periodically
///
/// Use this for high-frequency writes (logs, metrics) where per-write
/// atomic operations would be too expensive.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::io::{BatchedWriter, WriteOptions};
///
/// let mut writer = BatchedWriter::new("/path/to/log", WriteOptions::for_logs())?;
///
/// // Writes are buffered
/// writer.write(b"log entry 1\n")?;
/// writer.write(b"log entry 2\n")?;
///
/// // Flush to disk atomically (or wait for auto-flush)
/// writer.flush()?;
///
/// // Ensure all data is written before dropping
/// writer.close()?;
/// ```
///
/// # Auto-Flush Behavior
///
/// The buffer is automatically flushed when:
/// 1. Buffer size exceeds `max_buffer_size`
/// 2. Time since last flush exceeds `flush_interval`
/// 3. `flush()` is called explicitly
/// 4. `close()` is called
/// 5. The writer is dropped (best-effort, errors are ignored)
///
/// # Thread Safety
///
/// This type is NOT thread-safe. For concurrent access, wrap in a mutex
/// or use a channel-based approach with a dedicated writer thread.
pub struct BatchedWriter {
    /// Path to write to
    path: PathBuf,

    /// Write options
    options: WriteOptions,

    /// Internal buffer
    buffer: Vec<u8>,

    /// Maximum buffer size before auto-flush
    max_buffer_size: usize,

    /// Interval between auto-flushes
    flush_interval: Duration,

    /// Last flush time
    last_flush: Instant,

    /// Total bytes written (across all flushes)
    total_bytes_written: u64,

    /// Number of flushes performed
    flush_count: u64,
}

impl BatchedWriter {
    /// Create a new batched writer for the given path
    ///
    /// # Arguments
    ///
    /// * `path` - Target file path
    /// * `options` - Write options (mode, sync, etc.)
    ///
    /// # Note
    ///
    /// The file is NOT created until the first flush.
    pub fn new(path: impl AsRef<Path>, options: WriteOptions) -> Result<Self, Problem> {
        let path = path.as_ref();

        // Validate path early (but don't create file yet)
        if !options.follow_symlinks && path.exists() && path.is_symlink() {
            return Err(Problem::io(format!(
                "Path '{}' is a symlink and follow_symlinks is disabled",
                path.display()
            )));
        }

        if !options.overwrite && path.exists() {
            return Err(Problem::io(format!(
                "File '{}' already exists and overwrite is disabled",
                path.display()
            )));
        }

        Ok(Self {
            path: path.to_owned(),
            options,
            buffer: Vec::with_capacity(DEFAULT_MAX_BUFFER_SIZE),
            max_buffer_size: DEFAULT_MAX_BUFFER_SIZE,
            flush_interval: DEFAULT_FLUSH_INTERVAL,
            last_flush: Instant::now(),
            total_bytes_written: 0,
            flush_count: 0,
        })
    }

    /// Set maximum buffer size before auto-flush
    ///
    /// Default: 64 KB
    #[must_use]
    pub fn max_buffer_size(mut self, size: usize) -> Self {
        self.max_buffer_size = size;
        self.buffer
            .reserve(size.saturating_sub(self.buffer.capacity()));
        self
    }

    /// Set flush interval
    ///
    /// Default: 1 second
    #[must_use]
    pub fn flush_interval(mut self, interval: Duration) -> Self {
        self.flush_interval = interval;
        self
    }

    /// Append data to buffer
    ///
    /// Auto-flushes if buffer exceeds `max_buffer_size` or
    /// time since last flush exceeds `flush_interval`.
    ///
    /// # Errors
    ///
    /// Returns error if auto-flush fails.
    pub fn write(&mut self, data: &[u8]) -> Result<(), Problem> {
        self.buffer.extend_from_slice(data);

        // Check if we need to auto-flush
        if self.should_flush() {
            self.flush()?;
        }

        Ok(())
    }

    /// Write a line (appends newline)
    ///
    /// Convenience method for log-style writes.
    pub fn write_line(&mut self, line: &str) -> Result<(), Problem> {
        self.buffer.extend_from_slice(line.as_bytes());
        self.buffer.push(b'\n');

        if self.should_flush() {
            self.flush()?;
        }

        Ok(())
    }

    /// Check if buffer should be flushed
    fn should_flush(&self) -> bool {
        self.buffer.len() >= self.max_buffer_size
            || self.last_flush.elapsed() >= self.flush_interval
    }

    /// Force flush buffer to disk atomically
    ///
    /// This performs an atomic write of the entire buffer contents.
    /// After flush, the buffer is cleared.
    ///
    /// # Note
    ///
    /// If the file already exists, this APPENDS to it by reading
    /// existing content first. For pure overwrite behavior, use
    /// `flush_overwrite()`.
    pub fn flush(&mut self) -> Result<(), Problem> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        // Read existing content if file exists (append mode)
        let existing = if self.path.exists() {
            std::fs::read(&self.path).unwrap_or_default()
        } else {
            Vec::new()
        };

        // Combine existing + new
        let mut combined = existing;
        combined.extend_from_slice(&self.buffer);

        // Atomic write
        let mut writer = AtomicWriter::new(&self.path, self.options)?;
        writer.write_all(&combined).map_err(|e| {
            Problem::io(format!(
                "Failed to write to '{}': {}",
                self.path.display(),
                e
            ))
        })?;
        writer.commit()?;

        // Update stats (using saturating arithmetic to avoid overflow)
        self.total_bytes_written = self
            .total_bytes_written
            .saturating_add(self.buffer.len() as u64);
        self.flush_count = self.flush_count.saturating_add(1);
        self.last_flush = Instant::now();
        self.buffer.clear();

        Ok(())
    }

    /// Flush buffer, overwriting file entirely
    ///
    /// Unlike `flush()`, this does NOT append to existing content.
    pub fn flush_overwrite(&mut self) -> Result<(), Problem> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        // Atomic write (no append)
        let mut writer = AtomicWriter::new(&self.path, self.options)?;
        writer.write_all(&self.buffer).map_err(|e| {
            Problem::io(format!(
                "Failed to write to '{}': {}",
                self.path.display(),
                e
            ))
        })?;
        writer.commit()?;

        // Update stats (using saturating arithmetic to avoid overflow)
        self.total_bytes_written = self
            .total_bytes_written
            .saturating_add(self.buffer.len() as u64);
        self.flush_count = self.flush_count.saturating_add(1);
        self.last_flush = Instant::now();
        self.buffer.clear();

        Ok(())
    }

    /// Flush and close the writer
    ///
    /// Consumes the writer, ensuring all data is written.
    /// Prefer this over letting the writer drop to handle errors.
    pub fn close(mut self) -> Result<(), Problem> {
        self.flush()
    }

    /// Get the target path
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get current buffer size in bytes
    #[must_use]
    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    /// Get total bytes written (across all flushes)
    #[must_use]
    pub fn total_bytes_written(&self) -> u64 {
        self.total_bytes_written
    }

    /// Get number of flushes performed
    #[must_use]
    pub fn flush_count(&self) -> u64 {
        self.flush_count
    }

    /// Check if buffer is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Get time since last flush
    #[must_use]
    pub fn time_since_flush(&self) -> Duration {
        self.last_flush.elapsed()
    }
}

impl Drop for BatchedWriter {
    fn drop(&mut self) {
        // Best-effort flush on drop
        // We can't return errors from drop, so we ignore them
        let _ = self.flush();
    }
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
    fn test_batched_writer_basic() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("batched.txt");

        {
            let mut writer =
                BatchedWriter::new(&path, WriteOptions::default()).expect("create writer");

            writer.write(b"line 1\n").expect("write line 1");
            writer.write(b"line 2\n").expect("write line 2");
            writer.close().expect("close");
        }

        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "line 1\nline 2\n");
    }

    #[test]
    fn test_batched_writer_write_line() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("lines.txt");

        {
            let mut writer =
                BatchedWriter::new(&path, WriteOptions::default()).expect("create writer");

            writer.write_line("line 1").expect("write line 1");
            writer.write_line("line 2").expect("write line 2");
            writer.close().expect("close");
        }

        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "line 1\nline 2\n");
    }

    #[test]
    fn test_batched_writer_auto_flush_size() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("auto_flush.txt");

        {
            let mut writer = BatchedWriter::new(&path, WriteOptions::default())
                .expect("create writer")
                .max_buffer_size(10); // Small buffer for testing

            // Write more than buffer size
            writer.write(b"12345678901234567890").expect("write");

            // Should have auto-flushed
            assert_eq!(writer.flush_count(), 1);
        }
    }

    #[test]
    fn test_batched_writer_append_mode() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("append.txt");

        // First write
        {
            let mut writer =
                BatchedWriter::new(&path, WriteOptions::default()).expect("create writer");
            writer.write(b"first\n").expect("write");
            writer.close().expect("close");
        }

        // Second write (append)
        {
            let mut writer =
                BatchedWriter::new(&path, WriteOptions::default()).expect("create writer");
            writer.write(b"second\n").expect("write");
            writer.close().expect("close");
        }

        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "first\nsecond\n");
    }

    #[test]
    fn test_batched_writer_stats() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("stats.txt");

        let mut writer = BatchedWriter::new(&path, WriteOptions::default()).expect("create writer");

        assert_eq!(writer.buffer_len(), 0);
        assert!(writer.is_empty());
        assert_eq!(writer.total_bytes_written(), 0);
        assert_eq!(writer.flush_count(), 0);

        writer.write(b"hello").expect("write");
        assert_eq!(writer.buffer_len(), 5);
        assert!(!writer.is_empty());

        writer.flush().expect("flush");
        assert_eq!(writer.buffer_len(), 0);
        assert!(writer.is_empty());
        assert_eq!(writer.total_bytes_written(), 5);
        assert_eq!(writer.flush_count(), 1);
    }

    #[test]
    fn test_batched_writer_flush_empty() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("empty.txt");

        let mut writer = BatchedWriter::new(&path, WriteOptions::default()).expect("create writer");

        // Flush empty buffer should be no-op
        writer.flush().expect("flush");
        assert_eq!(writer.flush_count(), 0);
        assert!(!path.exists());
    }

    #[test]
    fn test_batched_writer_drop_flushes() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("drop.txt");

        {
            let mut writer =
                BatchedWriter::new(&path, WriteOptions::default()).expect("create writer");
            writer.write(b"auto flush on drop").expect("write");
            // Drop without explicit close
        }

        // Should have been flushed on drop
        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "auto flush on drop");
    }

    #[test]
    fn test_batched_writer_flush_overwrite() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("overwrite.txt");

        // Create initial file
        std::fs::write(&path, "original").expect("create file");

        {
            let mut writer =
                BatchedWriter::new(&path, WriteOptions::default()).expect("create writer");
            writer.write(b"new content").expect("write");
            writer.flush_overwrite().expect("flush overwrite");
        }

        let contents = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(contents, "new content");
    }

    #[test]
    fn test_batched_writer_configuration() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("config.txt");

        let writer = BatchedWriter::new(&path, WriteOptions::default())
            .expect("create writer")
            .max_buffer_size(1024)
            .flush_interval(Duration::from_millis(100));

        assert_eq!(writer.path(), path);
    }
}
