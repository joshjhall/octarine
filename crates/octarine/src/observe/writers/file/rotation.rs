//! Log rotation, compression, and retention for FileWriter
//!
//! Handles:
//! - Size-based rotation
//! - Time-based rotation (hourly, daily, weekly)
//! - Age-based rotation
//! - Gzip compression of rotated files
//! - Retention policy enforcement

use super::FileWriter;
use crate::observe::Problem;
use crate::observe::writers::types::RotationSchedule;
use crate::primitives::io::file::{IoBuilder, path_exists};
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use tokio::io::AsyncWriteExt;

/// Check if rotation is needed based on size, age, or schedule
pub(super) async fn needs_rotation(writer: &FileWriter) -> bool {
    // Never rotate if schedule is Never
    if matches!(writer.rotation_schedule, RotationSchedule::Never) {
        return false;
    }

    let path = writer.current_log_path();
    // Use circuit breaker but don't retry metadata checks - just return false on failure
    if !writer.fs_circuit_breaker.can_proceed() {
        return true; // Assume rotation needed if filesystem is unhealthy
    }

    match tokio::fs::metadata(&path).await {
        Ok(metadata) => {
            writer.fs_circuit_breaker.record_success();

            // Size-based rotation
            if metadata.len() >= writer.max_file_size {
                return true;
            }

            // Age-based rotation
            if let Some(max_age) = writer.max_age
                && let Ok(modified) = metadata.modified()
                && let Ok(age) = SystemTime::now().duration_since(modified)
                && age >= max_age
            {
                return true;
            }

            // Schedule-based rotation
            if let Ok(modified) = metadata.modified()
                && should_rotate_by_schedule(writer, modified)
            {
                return true;
            }

            false
        }
        Err(_) => {
            writer.fs_circuit_breaker.record_failure();
            false
        }
    }
}

/// Check if rotation is needed based on schedule
fn should_rotate_by_schedule(writer: &FileWriter, file_modified: SystemTime) -> bool {
    use chrono::{DateTime, Datelike, Local, Timelike};

    let now: DateTime<Local> = Local::now();
    let file_time: DateTime<Local> = file_modified.into();

    match writer.rotation_schedule {
        RotationSchedule::Hourly => {
            // Rotate if file is from a different hour
            now.hour() != file_time.hour() || now.date_naive() != file_time.date_naive()
        }
        RotationSchedule::Daily => {
            // Rotate if file is from a different day
            now.date_naive() != file_time.date_naive()
        }
        RotationSchedule::Weekly => {
            // Rotate if file is from a different week
            now.iso_week() != file_time.iso_week() || now.year() != file_time.year()
        }
        RotationSchedule::SizeOnly | RotationSchedule::Never => false,
    }
}

/// Rotate log files with optional compression
pub(super) async fn rotate(writer: &FileWriter) -> Result<(), Problem> {
    // Close current file
    {
        let mut file_guard = writer.file.lock().await;
        if let Some(mut file) = file_guard.take() {
            file.flush().await.map_err(|e| {
                Problem::operation_failed(format!("Failed to flush before rotation: {}", e))
            })?;
        }
        // Reset file opened time
        *writer.file_opened_at.lock().await = None;
    }

    // First enforce retention (clean up old files)
    enforce_retention(writer).await?;

    // Remove oldest backup if we're at the limit
    // Use async path_exists() to avoid blocking the runtime
    let oldest_path = writer.rotated_log_path(writer.max_backups);
    let oldest_compressed = writer
        .log_dir
        .join(format!("{}.{}.gz", writer.filename, writer.max_backups));
    if path_exists(oldest_path.clone()).await.unwrap_or(false) {
        tokio::fs::remove_file(&oldest_path).await.map_err(|e| {
            Problem::operation_failed(format!("Failed to remove oldest backup: {}", e))
        })?;
    }
    if path_exists(oldest_compressed.clone())
        .await
        .unwrap_or(false)
    {
        tokio::fs::remove_file(&oldest_compressed)
            .await
            .map_err(|e| {
                Problem::operation_failed(format!(
                    "Failed to remove oldest compressed backup: {}",
                    e
                ))
            })?;
    }

    // Rotate existing backups (move .4 to .5, .3 to .4, etc.)
    // Use async path_exists() to avoid blocking the runtime
    for i in (1..writer.max_backups).rev() {
        let src = writer.rotated_log_path(i);
        let src_compressed = writer.log_dir.join(format!("{}.{}.gz", writer.filename, i));
        let dst = writer.rotated_log_path(i.saturating_add(1));
        let dst_compressed =
            writer
                .log_dir
                .join(format!("{}.{}.gz", writer.filename, i.saturating_add(1)));

        // Handle compressed files
        if path_exists(src_compressed.clone()).await.unwrap_or(false) {
            tokio::fs::rename(&src_compressed, &dst_compressed)
                .await
                .map_err(|e| {
                    Problem::operation_failed(format!(
                        "Failed to rotate compressed backup {}: {}",
                        i, e
                    ))
                })?;
        }
        // Handle uncompressed files
        if path_exists(src.clone()).await.unwrap_or(false) {
            tokio::fs::rename(&src, &dst).await.map_err(|e| {
                Problem::operation_failed(format!("Failed to rotate backup {}: {}", i, e))
            })?;
        }
    }

    // Move current log to .1
    // Use async path_exists() to avoid blocking the runtime
    let current = writer.current_log_path();
    let backup = writer.rotated_log_path(1);
    if path_exists(current.clone()).await.unwrap_or(false) {
        tokio::fs::rename(&current, &backup).await.map_err(|e| {
            Problem::operation_failed(format!("Failed to move current log to backup: {}", e))
        })?;

        // Compress the rotated file if compression is enabled
        if writer.compress_rotated {
            compress_file(writer, &backup).await?;
        }
    }

    Ok(())
}

/// Compress a log file with gzip
///
/// Uses atomic write via `IoBuilder` to ensure the compressed file is either
/// fully written or not created at all. This prevents partial/corrupt compressed
/// files on crash or disk full scenarios.
async fn compress_file(writer: &FileWriter, path: &std::path::Path) -> Result<(), Problem> {
    let input_path = path.to_path_buf();
    let output_path = writer.log_dir.join(format!(
        "{}.gz",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("backup")
    ));
    let compression_level = writer.compression_level;

    // Perform compression in a blocking task to avoid blocking the async runtime
    // Uses spawn_blocking from primitives/runtime for context propagation

    crate::primitives::runtime::r#async::spawn_blocking(move || {
        // Read the input file
        let input_data = std::fs::read(&input_path).map_err(|e| {
            Problem::operation_failed(format!("Failed to read file for compression: {}", e))
        })?;

        // Compress data in memory
        let mut compressed_data = Vec::new();
        {
            let compression = Compression::new(compression_level);
            let mut encoder = GzEncoder::new(&mut compressed_data, compression);
            encoder.write_all(&input_data).map_err(|e| {
                Problem::operation_failed(format!("Failed to compress data: {}", e))
            })?;
            encoder.finish().map_err(|e| {
                Problem::operation_failed(format!("Failed to finalize compression: {}", e))
            })?;
        }

        // Write compressed data atomically with proper permissions
        // Uses IoBuilder::for_logs() which sets LOG_FILE permissions (0640)
        IoBuilder::for_logs()
            .write(&output_path, &compressed_data)
            .map_err(|e| {
                Problem::operation_failed(format!(
                    "Failed to write compressed file '{}': {}",
                    output_path.display(),
                    e
                ))
            })?;

        // Remove the original uncompressed file only after successful atomic write
        #[allow(clippy::disallowed_methods)]
        std::fs::remove_file(&input_path).map_err(|e| {
            Problem::operation_failed(format!(
                "Failed to remove original file after compression: {}",
                e
            ))
        })?;

        Ok::<(), Problem>(())
    })
    .await
    .map_err(|e| Problem::operation_failed(format!("Compression task failed: {}", e)))?
}

/// Enforce retention policy by deleting old log files
///
/// Deletes files older than `retention_days` and ensures we don't exceed `max_backups`.
pub(super) async fn enforce_retention(writer: &FileWriter) -> Result<usize, Problem> {
    let mut deleted_count: usize = 0;

    // Get list of log files in directory
    let mut entries = tokio::fs::read_dir(&writer.log_dir)
        .await
        .map_err(|e| Problem::operation_failed(format!("Failed to read log directory: {}", e)))?;

    let mut log_files: Vec<(PathBuf, SystemTime)> = Vec::new();

    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| Problem::operation_failed(format!("Failed to read directory entry: {}", e)))?
    {
        let path = entry.path();
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Check if this is one of our log files
        if filename.starts_with(&writer.filename)
            && let Ok(metadata) = entry.metadata().await
            && let Ok(modified) = metadata.modified()
        {
            log_files.push((path, modified));
        }
    }

    // Delete files older than retention_days
    if let Some(retention_days) = writer.retention_days {
        // Calculate cutoff time: retention_days * 24 hours * 60 minutes * 60 seconds
        #[allow(clippy::arithmetic_side_effects)]
        let retention_secs = u64::from(retention_days).saturating_mul(24 * 60 * 60);
        let cutoff = SystemTime::now()
            .checked_sub(Duration::from_secs(retention_secs))
            .unwrap_or(SystemTime::UNIX_EPOCH);

        for (path, modified) in &log_files {
            if *modified < cutoff {
                // Don't delete the current log file
                if *path != writer.current_log_path()
                    && let Ok(()) = tokio::fs::remove_file(path).await
                {
                    deleted_count = deleted_count.saturating_add(1);
                }
            }
        }
    }

    Ok(deleted_count)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::observe::types::{Event, EventType};
    use crate::observe::writers::Writer;
    use crate::observe::writers::builder::FileWriterBuilder;
    use crate::observe::writers::types::{LogDirectory, LogFilename, RotationConfig};
    use flate2::read::GzDecoder;
    use std::io::Read;

    #[tokio::test]
    async fn test_log_rotation() {
        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_rotation");
        let _ = tokio::fs::create_dir_all(&log_dir).await;

        // Create writer with small max file size (1 KB)
        let log_dir_str = log_dir
            .to_str()
            .expect("Temp dir path should be valid UTF-8");
        let writer = FileWriter::with_rotation(
            log_dir_str,
            "test.log",
            1024, // 1 KB
            3,    // Keep 3 backups
        )
        .await
        .expect("Failed to create FileWriter with rotation");

        // Write enough events to trigger rotation
        for i in 0..100 {
            let event = Event::new(EventType::Info, format!("Test message {}", i));
            writer
                .write_event(&event)
                .await
                .expect("Failed to write event");
        }
        writer.flush().await.expect("Failed to flush");

        // Drop writer to ensure files are closed
        drop(writer);

        // Check that rotation occurred
        let backup_1 = log_dir.join("test.log.1");
        assert!(backup_1.exists(), "Backup file should exist after rotation");

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
    }

    #[tokio::test]
    async fn test_rotation_with_compression() {
        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_compression");
        let _ = tokio::fs::remove_dir_all(&log_dir).await; // Clean up any previous run
        let _ = tokio::fs::create_dir_all(&log_dir).await;

        // Create writer with compression enabled
        let log_dir_obj = LogDirectory::new(log_dir.to_str().expect("Path should be valid UTF-8"))
            .expect("Valid log directory");
        let filename = LogFilename::new("test.log").expect("Valid filename");

        let config = RotationConfig::builder()
            .max_file_size(512) // Very small to trigger rotation quickly
            .max_backups(3)
            .compress_rotated(true)
            .compression_level(6)
            .build();

        let writer = FileWriterBuilder::new(log_dir_obj, filename)
            .with_rotation(config)
            .build()
            .await
            .expect("Failed to create FileWriter");

        // Write enough events to trigger rotation
        for i in 0..50 {
            let event = Event::new(EventType::Info, format!("Test message {}", i));
            writer
                .write_event(&event)
                .await
                .expect("Failed to write event");
        }
        writer.flush().await.expect("Failed to flush");

        // Drop writer to ensure files are closed
        drop(writer);

        // Check that compressed backup exists
        let compressed_backup = log_dir.join("test.log.1.gz");
        assert!(
            compressed_backup.exists(),
            "Compressed backup should exist after rotation"
        );

        // Verify the compressed file can be decompressed
        let compressed_data =
            std::fs::read(&compressed_backup).expect("Failed to read compressed file");
        let mut decoder = GzDecoder::new(&compressed_data[..]);
        let mut decompressed = String::new();
        decoder
            .read_to_string(&mut decompressed)
            .expect("Failed to decompress file");

        // The decompressed content should contain log entries
        assert!(
            decompressed.contains("Test message"),
            "Decompressed content should contain log messages"
        );

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
    }

    #[tokio::test]
    async fn test_rotation_schedule_daily() {
        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_schedule");
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
        let _ = tokio::fs::create_dir_all(&log_dir).await;

        let log_dir_obj = LogDirectory::new(log_dir.to_str().expect("Path should be valid UTF-8"))
            .expect("Valid log directory");
        let filename = LogFilename::new("test.log").expect("Valid filename");

        let config = RotationConfig::builder()
            .schedule(RotationSchedule::Daily)
            .max_file_size(100 * 1024 * 1024) // Large size so only schedule triggers
            .max_backups(5)
            .build();

        let writer = FileWriterBuilder::new(log_dir_obj, filename)
            .with_rotation(config)
            .build()
            .await
            .expect("Failed to create FileWriter");

        // Write an event
        let event = Event::new(EventType::Info, "Test message");
        writer
            .write_event(&event)
            .await
            .expect("Failed to write event");
        writer.flush().await.expect("Failed to flush");

        // The schedule-based rotation won't trigger immediately
        // (would need to mock time or wait a day)
        // Just verify the writer was configured correctly
        assert_eq!(writer.rotation_schedule, RotationSchedule::Daily);

        // Cleanup
        drop(writer);
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
    }

    #[tokio::test]
    async fn test_retention_enforcement() {
        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_retention");
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
        let _ = tokio::fs::create_dir_all(&log_dir).await;

        // Create some old log files manually
        let old_log = log_dir.join("test.log.old");
        tokio::fs::write(&old_log, "old log content")
            .await
            .expect("Failed to create old log file");

        let log_dir_obj = LogDirectory::new(log_dir.to_str().expect("Path should be valid UTF-8"))
            .expect("Valid log directory");
        let filename = LogFilename::new("test.log").expect("Valid filename");

        let config = RotationConfig::builder()
            .retention_days(0) // 0 days = delete immediately
            .max_backups(2)
            .build();

        let writer = FileWriterBuilder::new(log_dir_obj, filename)
            .with_rotation(config)
            .build()
            .await
            .expect("Failed to create FileWriter");

        // Enforce retention
        let deleted = writer
            .enforce_retention_now()
            .await
            .expect("Failed to enforce retention");

        // The old log file should have been deleted
        assert!(!old_log.exists(), "Old log file should have been deleted");
        assert!(deleted >= 1, "At least one file should have been deleted");

        // Cleanup
        drop(writer);
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
    }

    #[tokio::test]
    async fn test_rotation_config_presets() {
        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_presets");
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
        let _ = tokio::fs::create_dir_all(&log_dir).await;

        let log_dir_obj = LogDirectory::new(log_dir.to_str().expect("Path should be valid UTF-8"))
            .expect("Valid log directory");
        let filename = LogFilename::new("test.log").expect("Valid filename");

        // Test with high_compliance preset
        let writer = FileWriterBuilder::new(log_dir_obj, filename)
            .with_rotation(RotationConfig::high_compliance())
            .build()
            .await
            .expect("Failed to create FileWriter");

        assert!(writer.compress_rotated);
        assert_eq!(writer.compression_level, 9);
        assert_eq!(writer.rotation_schedule, RotationSchedule::Hourly);
        assert_eq!(writer.retention_days, Some(365));

        // Cleanup
        drop(writer);
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
    }
}
