//! JSONL query support for FileWriter
//!
//! Enables querying stored events from JSONL-formatted log files.

use super::FileWriter;
use crate::observe::types::Event;
use crate::observe::writers::query::{
    AuditQuery, ParseErrorInfo, QueryResult, filter_events, paginate_events_with_errors,
};
use crate::observe::writers::types::{LogFormat, WriterError};
use crate::primitives::io::file::path_exists;
use flate2::read::GzDecoder;
use std::path::PathBuf;

/// Query events from the FileWriter's log files
///
/// Only works with JSONL format. Human-readable format returns an error.
pub(super) async fn query_events(
    writer: &FileWriter,
    query: &AuditQuery,
) -> Result<QueryResult, WriterError> {
    // Only JSONL format supports querying
    if writer.format != LogFormat::JsonLines {
        return Err(WriterError::Other(
            "Query is only supported for JSONL format. Human-readable logs cannot be parsed reliably.".to_string()
        ));
    }

    // Collect log files to query
    let log_files = collect_log_files(writer).await?;

    // Parse events from files in a blocking task
    let (events, parse_errors) = parse_jsonl_files(log_files).await?;

    // Apply filters
    let filtered = filter_events(&events, query);

    // Apply pagination (include parse errors for diagnostics)
    let result = paginate_events_with_errors(filtered, query, parse_errors);

    Ok(result)
}

/// Collect all log files (current + rotated) in the log directory
async fn collect_log_files(writer: &FileWriter) -> Result<Vec<PathBuf>, WriterError> {
    let mut files = Vec::new();

    // Current log file
    let current = writer.current_log_path();
    if path_exists(current.clone()).await.unwrap_or(false) {
        files.push(current);
    }

    // Rotated log files (both compressed and uncompressed)
    for i in 1..=writer.max_backups {
        let rotated = writer.rotated_log_path(i);
        let rotated_gz = writer.log_dir.join(format!("{}.{}.gz", writer.filename, i));

        if path_exists(rotated.clone()).await.unwrap_or(false) {
            files.push(rotated);
        }
        if path_exists(rotated_gz.clone()).await.unwrap_or(false) {
            files.push(rotated_gz);
        }
    }

    Ok(files)
}

/// Parse JSONL files and return events with any parse errors
///
/// Handles both plain text and gzip-compressed files.
/// Returns a tuple of (events, parse_errors) to provide visibility
/// into any lines that could not be parsed.
async fn parse_jsonl_files(
    files: Vec<PathBuf>,
) -> Result<(Vec<Event>, Vec<ParseErrorInfo>), WriterError> {
    use std::io::{BufRead, BufReader};

    // Move file parsing to a blocking task

    crate::primitives::runtime::r#async::spawn_blocking(move || {
        let mut events = Vec::new();
        let mut parse_errors = Vec::new();

        for file_path in files {
            let file_path_str = file_path.display().to_string();

            let content = if file_path.extension().is_some_and(|ext| ext == "gz") {
                // Compressed file
                read_gzip_file(&file_path)?
            } else {
                // Plain text file
                read_plain_file(&file_path)?
            };

            // Parse JSONL
            let reader = BufReader::new(content.as_bytes());
            for (line_idx, line_result) in reader.lines().enumerate() {
                let line_number = line_idx.saturating_add(1); // 1-indexed

                let line = match line_result {
                    Ok(l) => l,
                    Err(e) => {
                        parse_errors.push(ParseErrorInfo::new(
                            file_path_str.clone(),
                            line_number,
                            format!("IO error: {}", e),
                            "<unreadable>",
                        ));
                        continue;
                    }
                };

                // Skip empty lines
                if line.trim().is_empty() {
                    continue;
                }

                // Parse JSON line
                match serde_json::from_str::<Event>(&line) {
                    Ok(event) => events.push(event),
                    Err(e) => {
                        parse_errors.push(ParseErrorInfo::new(
                            file_path_str.clone(),
                            line_number,
                            e.to_string(),
                            &line,
                        ));
                    }
                }
            }
        }

        Ok::<(Vec<Event>, Vec<ParseErrorInfo>), WriterError>((events, parse_errors))
    })
    .await
    .map_err(|e| WriterError::Other(format!("Failed to spawn blocking task: {}", e)))?
}

/// Read a plain text file
fn read_plain_file(path: &std::path::Path) -> Result<String, WriterError> {
    std::fs::read_to_string(path).map_err(WriterError::Io)
}

/// Read and decompress a gzip file
fn read_gzip_file(path: &std::path::Path) -> Result<String, WriterError> {
    use std::io::Read;

    let file = std::fs::File::open(path).map_err(WriterError::Io)?;
    let mut decoder = GzDecoder::new(file);
    let mut content = String::new();
    decoder
        .read_to_string(&mut content)
        .map_err(|e| WriterError::Other(format!("Failed to decompress gzip file: {}", e)))?;
    Ok(content)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::observe::types::{Event, EventType, Severity};
    use crate::observe::writers::Writer;
    use crate::observe::writers::builder::FileWriterBuilder;
    use crate::observe::writers::query::Queryable;
    use crate::observe::writers::types::{LogDirectory, LogFilename};

    #[tokio::test]
    async fn test_queryable_jsonl_basic() {
        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_queryable_basic");
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

        // Write some events
        for i in 0..5 {
            let event = Event::new(EventType::Info, format!("Query test event {}", i));
            writer
                .write_event(&event)
                .await
                .expect("Failed to write event");
        }
        writer.flush().await.expect("Failed to flush");

        // Query all events
        let query = AuditQuery::default();
        let result = writer.query(&query).await.expect("Query should succeed");

        assert_eq!(result.events.len(), 5, "Should find all 5 events");

        // Cleanup
        drop(writer);
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
    }

    #[tokio::test]
    async fn test_queryable_human_readable_fails() {
        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_queryable_human");
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
        let _ = tokio::fs::create_dir_all(&log_dir).await;

        let log_dir_obj = LogDirectory::new(log_dir.to_str().expect("Path should be valid UTF-8"))
            .expect("Valid log directory");
        let filename = LogFilename::new("test.log").expect("Valid filename");

        let writer = FileWriterBuilder::new(log_dir_obj, filename)
            .with_format(LogFormat::HumanReadable)
            .build()
            .await
            .expect("Failed to create FileWriter");

        // Write an event
        let event = Event::new(EventType::Info, "Test event");
        writer
            .write_event(&event)
            .await
            .expect("Failed to write event");
        writer.flush().await.expect("Failed to flush");

        // Query should fail for human-readable format
        let query = AuditQuery::default();
        let result = writer.query(&query).await;

        assert!(
            result.is_err(),
            "Query should fail for human-readable format"
        );

        // Cleanup
        drop(writer);
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
    }

    #[tokio::test]
    async fn test_queryable_with_filters() {
        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_queryable_filters");
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
        let _ = tokio::fs::create_dir_all(&log_dir).await;

        let log_dir_obj = LogDirectory::new(log_dir.to_str().expect("Path should be valid UTF-8"))
            .expect("Valid log directory");
        let filename = LogFilename::new("test.jsonl").expect("Valid filename");

        let writer = FileWriterBuilder::new(log_dir_obj, filename)
            .with_format(LogFormat::JsonLines)
            .with_min_severity(Severity::Debug) // Allow all severities
            .build()
            .await
            .expect("Failed to create FileWriter");

        // Write events of different types and severities
        let info_event = Event::new(EventType::Info, "Info event");
        let warning_event = Event::new(EventType::Warning, "Warning event");
        let error_event = Event::new(EventType::ValidationError, "Error event");

        writer
            .write_event(&info_event)
            .await
            .expect("Failed to write");
        writer
            .write_event(&warning_event)
            .await
            .expect("Failed to write");
        writer
            .write_event(&error_event)
            .await
            .expect("Failed to write");
        writer.flush().await.expect("Failed to flush");

        // Query only warnings and above
        let query = AuditQuery {
            min_severity: Some(Severity::Warning),
            ..Default::default()
        };
        let result = writer.query(&query).await.expect("Query should succeed");

        assert_eq!(
            result.events.len(),
            2,
            "Should find 2 events (warning + error)"
        );

        // Cleanup
        drop(writer);
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
    }

    #[tokio::test]
    async fn test_queryable_with_pagination() {
        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_queryable_pagination");
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

        // Write 10 events
        for i in 0..10 {
            let event = Event::new(EventType::Info, format!("Pagination test {}", i));
            writer.write_event(&event).await.expect("Failed to write");
        }
        writer.flush().await.expect("Failed to flush");

        // Query first page (3 events)
        let query = AuditQuery {
            limit: Some(3),
            offset: Some(0),
            ..Default::default()
        };
        let result = writer.query(&query).await.expect("Query should succeed");

        assert_eq!(result.events.len(), 3, "First page should have 3 events");
        assert!(result.has_more, "Should have more results");

        // Query second page
        let query = AuditQuery {
            limit: Some(3),
            offset: Some(3),
            ..Default::default()
        };
        let result = writer.query(&query).await.expect("Query should succeed");

        assert_eq!(result.events.len(), 3, "Second page should have 3 events");
        assert!(result.has_more, "Should have more results");

        // Cleanup
        drop(writer);
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
    }

    #[tokio::test]
    async fn test_queryable_parse_errors() {
        let temp_dir = std::env::temp_dir();
        let log_dir = temp_dir.join("test_queryable_parse_errors");
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

        // Write some valid events
        for i in 0..3 {
            let event = Event::new(EventType::Info, format!("Valid event {}", i));
            writer.write_event(&event).await.expect("Failed to write");
        }
        writer.flush().await.expect("Failed to flush");

        // Now manually append some invalid lines directly to the file
        let log_path = log_dir.join("test.jsonl");
        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .await
            .expect("Failed to open log file");

        use tokio::io::AsyncWriteExt;
        // Invalid JSON
        file.write_all(b"this is not valid json\n")
            .await
            .expect("Failed to write invalid line");
        // Partial JSON
        file.write_all(b"{\"id\": \"incomplete\n")
            .await
            .expect("Failed to write partial line");
        file.flush().await.expect("Failed to flush");

        drop(file);

        // Query should still succeed but report parse errors
        let query = AuditQuery::default();
        let result = writer
            .query(&query)
            .await
            .expect("Query should still succeed");

        // Should have the 3 valid events
        assert_eq!(result.events.len(), 3, "Should find 3 valid events");

        // Should report parse errors
        assert!(result.is_parse_error_present(), "Should have parse errors");
        assert_eq!(result.parse_error_count(), 2, "Should have 2 parse errors");

        // Check parse error details
        let errors = &result.parse_errors;
        assert!(errors[0].line_number == 4 || errors[1].line_number == 4);
        assert!(
            errors[0].line_preview.contains("not valid json")
                || errors[1].line_preview.contains("not valid json")
        );

        // Cleanup
        drop(writer);
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
    }
}
