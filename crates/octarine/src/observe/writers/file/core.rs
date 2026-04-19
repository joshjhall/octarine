//! Core file operations for FileWriter
//!
//! Contains file management, formatting, and retry logic.

use super::FileWriter;
use super::rotation;
use crate::observe::Problem;
use crate::observe::types::{Event, Severity};
use crate::observe::writers::builder::FileWriterBuilder;
use crate::observe::writers::sanitize_for_writing;
use crate::observe::writers::types::LogFormat;
use crate::primitives::io::file::ensure_directory_mode;
#[cfg(unix)]
use crate::primitives::io::file::set_mode;
use crate::primitives::runtime::r#async::{
    CircuitBreaker, CircuitBreakerConfig, RetryPolicy, sleep_ms,
};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::fs::{File, OpenOptions};
use tokio::sync::Mutex;

/// Create a FileWriter from a builder
pub(super) async fn from_builder(builder: FileWriterBuilder) -> Result<FileWriter, Problem> {
    let log_dir = builder.log_dir();
    let filename = builder.filename();
    let rotation = builder.rotation();
    let dir_mode = builder.dir_mode();
    let file_mode = builder.file_mode();
    let durability = builder.durability();
    let format = builder.format();

    // Create directory if it doesn't exist and set secure permissions
    // Type system guarantees log_dir is valid and absolute
    let dir_path = log_dir.as_path().to_path_buf();
    crate::primitives::runtime::r#async::spawn_blocking(move || {
        ensure_directory_mode(&dir_path, dir_mode)
    })
    .await
    .map_err(|e| Problem::operation_failed(format!("Directory setup task failed: {}", e)))?
    .map_err(|e| {
        Problem::operation_failed(format!(
            "Failed to create/secure log directory {:?}: {}",
            log_dir.as_path(),
            e
        ))
    })?;

    // On non-Unix platforms, file-level permission enforcement is a no-op.
    // Warn the operator so audit-grade log isolation gaps are visible, rather
    // than silently discarding the configured FileMode.
    #[cfg(not(unix))]
    {
        crate::observe::warn(
            "observe.writers.file",
            format!(
                "FileWriter on non-Unix platform: configured file_mode={} will not be enforced (set_mode is a no-op). Secure the log directory via OS-level ACLs.",
                file_mode
            ),
        );
    }

    // Configure circuit breaker for filesystem operations
    // Uses high-availability preset: quick to open (3 failures), needs 80% success to close
    let fs_circuit_breaker = Arc::new(CircuitBreaker::with_config(
        CircuitBreakerConfig::high_availability(),
    ));

    // Configure retry policy for transient I/O failures
    // Use network preset: 5 attempts, 100ms base, 30s max with exponential backoff
    let retry_policy = RetryPolicy::network();

    // Timeout for individual file operations (5 seconds)
    // This prevents hangs on network filesystems
    let operation_timeout = Duration::from_secs(5);

    Ok(FileWriter {
        log_dir: log_dir.as_path().to_path_buf(),
        filename: filename.as_str().to_string(),
        min_severity: builder.min_severity(),
        max_file_size: rotation.max_file_size,
        max_backups: rotation.max_backups,
        rotation_schedule: rotation.schedule,
        max_age: rotation.max_age,
        compress_rotated: rotation.compress_rotated,
        compression_level: rotation.compression_level,
        retention_days: rotation.retention_days,
        file_mode,
        dir_mode,
        durability,
        format,
        file: Mutex::new(None),
        file_opened_at: Mutex::new(None),
        fs_circuit_breaker,
        retry_policy,
        operation_timeout,
    })
}

/// Execute an async operation with retry, timeout, and circuit breaker protection
pub(super) async fn with_retry<F, Fut, T>(writer: &FileWriter, operation: F) -> Result<T, Problem>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, Problem>>,
{
    let mut last_error = None;

    for attempt in 0..writer.retry_policy.max_attempts {
        // Check circuit breaker first
        if !writer.fs_circuit_breaker.can_proceed() {
            return Err(Problem::OperationFailed(
                "Filesystem circuit breaker is open - too many recent failures".into(),
            ));
        }

        // Execute with timeout protection
        let result = tokio::time::timeout(writer.operation_timeout, operation()).await;

        match result {
            Ok(Ok(value)) => {
                writer.fs_circuit_breaker.record_success();
                return Ok(value);
            }
            Ok(Err(e)) => {
                // Operation failed (not timeout)
                writer.fs_circuit_breaker.record_failure();
                last_error = Some(e);
            }
            Err(_) => {
                // Timeout
                writer.fs_circuit_breaker.record_failure();
                last_error = Some(Problem::Timeout(format!(
                    "File operation timed out after {:?}",
                    writer.operation_timeout
                )));
            }
        }

        // Don't sleep after last attempt
        #[allow(clippy::arithmetic_side_effects)] // Safe: max_attempts is always >= 1
        if attempt < writer.retry_policy.max_attempts - 1 {
            let delay = writer.retry_policy.backoff.delay(attempt);
            sleep_ms(delay.as_millis() as u64).await;
        }
    }

    Err(last_error
        .unwrap_or_else(|| Problem::OperationFailed("Operation failed after retries".into())))
}

/// Get or create the current log file
pub(super) async fn get_file(
    writer: &FileWriter,
) -> Result<tokio::sync::MutexGuard<'_, Option<File>>, Problem> {
    let mut file_guard = writer.file.lock().await;

    // Check if we need to rotate
    if rotation::needs_rotation(writer).await {
        drop(file_guard);
        rotation::rotate(writer).await?;
        file_guard = writer.file.lock().await;
    }

    // Open file if not already open - use retry with circuit breaker
    if file_guard.is_none() {
        let path = writer.current_log_path();
        let path_clone = path.clone();
        let file = with_retry(writer, || {
            let p = path_clone.clone();
            async move {
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&p)
                    .await
                    .map_err(|e| {
                        Problem::OperationFailed(format!(
                            "Failed to open log file {}: {}",
                            p.display(),
                            e
                        ))
                    })
            }
        })
        .await?;

        // Set file permissions based on configuration
        // This is done after open to handle both create and existing file cases
        #[cfg(unix)]
        {
            let path_for_perms = path.clone();
            let file_mode = writer.file_mode;
            crate::primitives::runtime::r#async::spawn_blocking(move || {
                set_mode(&path_for_perms, file_mode)
            })
            .await
            .map_err(|e| Problem::operation_failed(format!("Permission task failed: {}", e)))?
            .map_err(|e| {
                Problem::operation_failed(format!("Failed to set log file permissions: {}", e))
            })?;
        }

        *file_guard = Some(file);

        // Record when file was opened
        *writer.file_opened_at.lock().await = Some(SystemTime::now());
    }

    Ok(file_guard)
}

/// Format an event as a log line based on the configured format
pub(super) fn format_event(writer: &FileWriter, event: &Event) -> String {
    match writer.format {
        LogFormat::HumanReadable => format_event_human(event),
        LogFormat::JsonLines => format_event_jsonl(writer, event),
    }
}

/// Format an event as human-readable text
fn format_event_human(event: &Event) -> String {
    let timestamp = event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f");
    let level = match event.severity {
        Severity::Debug => "DEBUG",
        Severity::Info => "INFO",
        Severity::Warning => "WARN",
        Severity::Error => "ERROR",
        Severity::Critical => "CRITICAL",
    };

    // Build the log line
    let mut output = String::new();
    output.push_str(&format!("[{}] {} ", timestamp, level));

    // Add operation if present
    if !event.context.operation.is_empty() {
        output.push_str(&format!("{}: ", event.context.operation));
    }

    // Add message (with writer-level PII protection)
    // This provides defense-in-depth - even if event-level redaction was bypassed,
    // we scan the final output message before writing to disk
    let safe_message = sanitize_for_writing(&event.message);
    output.push_str(&safe_message);

    // Add context metadata
    if let Some(ref tenant) = event.context.tenant_id {
        output.push_str(&format!(" tenant={}", tenant));
    }
    if let Some(ref user) = event.context.user_id {
        output.push_str(&format!(" user={}", user));
    }
    if !event.context.file.is_empty() {
        output.push_str(&format!(
            " source={}:{}",
            event.context.file, event.context.line
        ));
    }

    output.push('\n');
    output
}

/// Format an event as JSON Lines (one JSON object per line)
///
/// Creates a sanitized copy of the event with PII redacted,
/// then serializes to JSON. Each line is a complete, valid JSON object.
fn format_event_jsonl(_writer: &FileWriter, event: &Event) -> String {
    // Create a sanitized version of the event for JSONL output
    // We need to redact PII from the message and any string values in metadata
    let sanitized_event = sanitize_event_for_jsonl(event);

    // Serialize to JSON - if serialization fails, fall back to human-readable
    match serde_json::to_string(&sanitized_event) {
        Ok(json) => format!("{}\n", json),
        Err(e) => {
            // Log serialization error and fall back to human-readable format
            let fallback = format!(
                "[{}] {} JSONL_SERIALIZATION_ERROR: {} - falling back to human format\n",
                event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
                "ERROR",
                e
            );
            format!("{}{}", fallback, format_event_human(event))
        }
    }
}

/// Create a sanitized copy of an event for JSONL output
///
/// Applies PII redaction to:
/// - Message field
/// - String values in metadata
fn sanitize_event_for_jsonl(event: &Event) -> Event {
    use serde_json::Value;

    // Sanitize message
    let safe_message = sanitize_for_writing(&event.message);

    // Sanitize metadata string values
    let safe_metadata: std::collections::HashMap<String, Value> = event
        .metadata
        .iter()
        .map(|(k, v)| {
            let safe_value = match v {
                Value::String(s) => Value::String(sanitize_for_writing(s)),
                // Recursively handle nested objects
                Value::Object(obj) => {
                    let safe_obj: serde_json::Map<String, Value> = obj
                        .iter()
                        .map(|(k, v)| {
                            let sv = if let Value::String(s) = v {
                                Value::String(sanitize_for_writing(s))
                            } else {
                                v.clone()
                            };
                            (k.clone(), sv)
                        })
                        .collect();
                    Value::Object(safe_obj)
                }
                // Arrays might contain strings
                Value::Array(arr) => {
                    let safe_arr: Vec<Value> = arr
                        .iter()
                        .map(|v| {
                            if let Value::String(s) = v {
                                Value::String(sanitize_for_writing(s))
                            } else {
                                v.clone()
                            }
                        })
                        .collect();
                    Value::Array(safe_arr)
                }
                // Numbers, bools, null - pass through
                other => other.clone(),
            };
            (k.clone(), safe_value)
        })
        .collect();

    Event {
        id: event.id,
        timestamp: event.timestamp,
        event_type: event.event_type,
        severity: event.severity,
        message: safe_message,
        context: event.context.clone(),
        metadata: safe_metadata,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::observe::types::{Event, EventContext, EventType};
    use crate::observe::writers::Writer;
    use crate::observe::writers::builder::FileWriterBuilder;
    use crate::observe::writers::types::{LogDirectory, LogFilename};

    #[tokio::test]
    async fn test_write_with_pii_redaction() {
        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_pii_redaction");
        tokio::fs::create_dir_all(&log_dir)
            .await
            .expect("Failed to create test dir");

        let log_dir_str = log_dir
            .to_str()
            .expect("Temp dir path should be valid UTF-8");
        let writer = FileWriter::new(log_dir_str, "test.log")
            .await
            .expect("Failed to create FileWriter");

        // Create an event with PII
        let mut event = Event::new(
            EventType::Info,
            "User SSN is 517-29-8346 and card is 4242424242424242",
        );
        event.context = EventContext::default();

        // Write the event
        writer
            .write_event(&event)
            .await
            .expect("Failed to write event");
        writer.flush().await.expect("Failed to flush");

        // Drop writer to ensure file is closed
        drop(writer);

        // Read the log file
        let log_path = log_dir.join("test.log");
        let contents = tokio::fs::read_to_string(&log_path)
            .await
            .expect("Failed to read log file");

        // PII should be redacted at writer level
        assert!(!contents.contains("517-29-8346"), "SSN was not redacted");
        assert!(
            !contents.contains("4242424242424242"),
            "Credit card was not redacted"
        );

        // Cleanup
        tokio::fs::remove_dir_all(&log_dir)
            .await
            .expect("Failed to cleanup");
    }

    #[tokio::test]
    async fn test_jsonl_format_basic() {
        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_jsonl_basic");
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
        let _ = tokio::fs::create_dir_all(&log_dir).await;

        let log_dir_obj = LogDirectory::new(log_dir.to_str().expect("Path should be valid UTF-8"))
            .expect("Valid log directory");
        let filename = LogFilename::new("test.jsonl").expect("Valid filename");

        let writer = FileWriterBuilder::new(log_dir_obj, filename)
            .with_format(LogFormat::JsonLines)
            .build()
            .await
            .expect("Failed to create FileWriter");

        // Verify format is set correctly
        assert_eq!(writer.format, LogFormat::JsonLines);

        // Write an event
        let event = Event::new(EventType::Info, "Test JSONL message");
        writer
            .write_event(&event)
            .await
            .expect("Failed to write event");
        writer.flush().await.expect("Failed to flush");

        // Drop writer to ensure file is closed
        drop(writer);

        // Read and verify JSONL output
        let log_path = log_dir.join("test.jsonl");
        let contents = tokio::fs::read_to_string(&log_path)
            .await
            .expect("Failed to read log file");

        // Each line should be valid JSON
        for line in contents.lines() {
            let parsed: serde_json::Value =
                serde_json::from_str(line).expect("Line should be valid JSON");
            assert!(parsed.is_object(), "Each line should be a JSON object");
            assert!(parsed.get("id").is_some(), "Should have id field");
            assert!(
                parsed.get("timestamp").is_some(),
                "Should have timestamp field"
            );
            assert!(
                parsed.get("severity").is_some(),
                "Should have severity field"
            );
            assert!(parsed.get("message").is_some(), "Should have message field");
        }

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
    }

    #[tokio::test]
    async fn test_jsonl_format_roundtrip() {
        use crate::observe::types::Event;

        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_jsonl_roundtrip");
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
        let _ = tokio::fs::create_dir_all(&log_dir).await;

        let log_dir_obj = LogDirectory::new(log_dir.to_str().expect("Path should be valid UTF-8"))
            .expect("Valid log directory");
        let filename = LogFilename::new("test.jsonl").expect("Valid filename");

        let writer = FileWriterBuilder::new(log_dir_obj, filename)
            .with_format(LogFormat::JsonLines)
            .build()
            .await
            .expect("Failed to create FileWriter");

        // Create event with metadata
        let mut event = Event::new(EventType::LoginSuccess, "User login successful");
        event.metadata.insert(
            "login_method".to_string(),
            serde_json::Value::String("oauth".to_string()),
        );
        event.metadata.insert(
            "ip_address".to_string(),
            serde_json::Value::String("192.168.1.1".to_string()),
        );

        writer
            .write_event(&event)
            .await
            .expect("Failed to write event");
        writer.flush().await.expect("Failed to flush");

        // Drop writer to ensure file is closed
        drop(writer);

        // Read and parse back
        let log_path = log_dir.join("test.jsonl");
        let contents = tokio::fs::read_to_string(&log_path)
            .await
            .expect("Failed to read log file");

        let line = contents
            .lines()
            .next()
            .expect("Should have at least one line");
        let parsed: Event = serde_json::from_str(line).expect("Should deserialize back to Event");

        // Verify roundtrip
        assert_eq!(parsed.id, event.id);
        assert_eq!(parsed.event_type, event.event_type);
        assert_eq!(parsed.message, event.message);
        assert!(parsed.metadata.contains_key("login_method"));
        assert!(parsed.metadata.contains_key("ip_address"));

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
    }

    #[tokio::test]
    async fn test_jsonl_pii_redaction() {
        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_jsonl_pii");
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
        let _ = tokio::fs::create_dir_all(&log_dir).await;

        let log_dir_obj = LogDirectory::new(log_dir.to_str().expect("Path should be valid UTF-8"))
            .expect("Valid log directory");
        let filename = LogFilename::new("test.jsonl").expect("Valid filename");

        let writer = FileWriterBuilder::new(log_dir_obj, filename)
            .with_format(LogFormat::JsonLines)
            .build()
            .await
            .expect("Failed to create FileWriter");

        // Create event with PII
        let mut event = Event::new(
            EventType::Info,
            "User SSN is 517-29-8346 and card is 4242424242424242",
        );
        event.metadata.insert(
            "credit_card".to_string(),
            serde_json::Value::String("4111111111111111".to_string()),
        );

        writer
            .write_event(&event)
            .await
            .expect("Failed to write event");
        writer.flush().await.expect("Failed to flush");

        // Drop writer to ensure file is closed
        drop(writer);

        // Read and verify PII is redacted
        let log_path = log_dir.join("test.jsonl");
        let contents = tokio::fs::read_to_string(&log_path)
            .await
            .expect("Failed to read log file");

        // PII should be redacted
        assert!(!contents.contains("517-29-8346"), "SSN should be redacted");
        assert!(
            !contents.contains("4242424242424242"),
            "Credit card should be redacted"
        );
        assert!(
            !contents.contains("4111111111111111"),
            "Credit card in metadata should be redacted"
        );

        // Should still be valid JSONL
        for line in contents.lines() {
            let _parsed: serde_json::Value = serde_json::from_str(line)
                .expect("Line should still be valid JSON after redaction");
        }

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
    }

    #[tokio::test]
    async fn test_jsonl_multiple_events() {
        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_jsonl_multiple");
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
        let _ = tokio::fs::create_dir_all(&log_dir).await;

        let log_dir_obj = LogDirectory::new(log_dir.to_str().expect("Path should be valid UTF-8"))
            .expect("Valid log directory");
        let filename = LogFilename::new("test.jsonl").expect("Valid filename");

        let writer = FileWriterBuilder::new(log_dir_obj, filename)
            .with_format(LogFormat::JsonLines)
            .build()
            .await
            .expect("Failed to create FileWriter");

        // Write multiple events
        for i in 0..10 {
            let event = Event::new(EventType::Info, format!("Event number {}", i));
            writer
                .write_event(&event)
                .await
                .expect("Failed to write event");
        }
        writer.flush().await.expect("Failed to flush");

        // Drop writer to ensure file is closed
        drop(writer);

        // Read and verify multiple lines
        let log_path = log_dir.join("test.jsonl");
        let contents = tokio::fs::read_to_string(&log_path)
            .await
            .expect("Failed to read log file");

        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 10, "Should have 10 events");

        // Each line should be independent valid JSON
        for (i, line) in lines.iter().enumerate() {
            let parsed: serde_json::Value =
                serde_json::from_str(line).expect("Each line should be valid JSON");
            let message = parsed
                .get("message")
                .and_then(|m| m.as_str())
                .expect("JSON should have message field");
            assert!(
                message.contains(&format!("Event number {}", i)),
                "Messages should be in order"
            );
        }

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
    }

    #[tokio::test]
    async fn test_human_readable_format_unchanged() {
        // Verify that human-readable format still works correctly
        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_human_format");
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
        let _ = tokio::fs::create_dir_all(&log_dir).await;

        let log_dir_obj = LogDirectory::new(log_dir.to_str().expect("Path should be valid UTF-8"))
            .expect("Valid log directory");
        let filename = LogFilename::new("test.log").expect("Valid filename");

        // Explicitly use HumanReadable format (default)
        let writer = FileWriterBuilder::new(log_dir_obj, filename)
            .with_format(LogFormat::HumanReadable)
            .build()
            .await
            .expect("Failed to create FileWriter");

        assert_eq!(writer.format, LogFormat::HumanReadable);

        let event = Event::new(EventType::Warning, "Human readable test");
        writer
            .write_event(&event)
            .await
            .expect("Failed to write event");
        writer.flush().await.expect("Failed to flush");

        drop(writer);

        let log_path = log_dir.join("test.log");
        let contents = tokio::fs::read_to_string(&log_path)
            .await
            .expect("Failed to read log file");

        // Human readable format should have traditional log format
        assert!(contents.contains("WARN"), "Should contain severity");
        assert!(
            contents.contains("Human readable test"),
            "Should contain message"
        );
        assert!(contents.contains("["), "Should have timestamp brackets");

        // Should NOT be JSON
        let is_json: Result<serde_json::Value, _> = serde_json::from_str(contents.trim());
        assert!(is_json.is_err(), "Human readable should not be valid JSON");

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
    }
}
