//! Integration tests for FileWriter
//!
//! Tests file-based logging including:
//! - Path validation and security
//! - Severity filtering
//! - JSONL format and queryability
//! - Rotation behavior

#![allow(clippy::panic, clippy::expect_used)]

use octarine::observe::writers::{
    AuditQuery, LogDirectory, LogFilename, LogFormat, RotationConfig,
};
use octarine::observe::{Event, EventType, Severity};
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper to create a temporary log directory
fn temp_log_dir() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("failed to create temp dir");
    let path = dir.path().to_path_buf();
    (dir, path)
}

// ============================================================================
// Path Validation Tests
// ============================================================================

#[test]
fn test_log_directory_rejects_relative_paths() {
    let result = LogDirectory::new("relative/path");
    assert!(result.is_err(), "Relative paths should be rejected");
}

#[test]
fn test_log_directory_rejects_command_injection() {
    let result = LogDirectory::new("/tmp/$(whoami)/logs");
    assert!(result.is_err(), "Command injection should be rejected");
}

#[test]
fn test_log_directory_rejects_shell_metacharacters() {
    let result = LogDirectory::new("/tmp; rm -rf /");
    assert!(result.is_err(), "Shell metacharacters should be rejected");
}

#[test]
fn test_log_directory_accepts_valid_absolute_path() {
    let (_dir, path) = temp_log_dir();
    let path_str = path.to_str().expect("valid UTF-8");
    let result = LogDirectory::new(path_str);
    assert!(result.is_ok(), "Valid absolute path should be accepted");
}

#[test]
fn test_log_filename_sanitizes_path_traversal() {
    // LogFilename sanitizes rather than rejects path traversal
    let result = LogFilename::new("../../../etc/passwd");
    assert!(
        result.is_ok(),
        "Path traversal should be sanitized, not rejected"
    );

    let filename = result.expect("sanitization succeeded");
    assert!(
        !filename.as_str().contains(".."),
        "Sanitized filename should not contain .."
    );
    assert!(
        !filename.as_str().contains('/'),
        "Sanitized filename should not contain /"
    );
}

#[test]
fn test_log_filename_sanitizes_absolute_path() {
    // LogFilename sanitizes absolute paths by stripping the leading /
    let result = LogFilename::new("/etc/passwd");
    assert!(
        result.is_ok(),
        "Absolute paths should be sanitized, not rejected"
    );

    let filename = result.expect("sanitization succeeded");
    assert!(
        !filename.as_str().starts_with('/'),
        "Sanitized filename should not start with /"
    );
}

#[test]
fn test_log_filename_accepts_simple_name() {
    let result = LogFilename::new("app.log");
    assert!(result.is_ok(), "Simple filename should be accepted");
}

#[test]
fn test_log_filename_accepts_jsonl_extension() {
    let result = LogFilename::new("audit.jsonl");
    assert!(result.is_ok(), "JSONL extension should be accepted");
}

// ============================================================================
// Rotation Configuration Tests
// ============================================================================

#[test]
fn test_rotation_config_builder_defaults() {
    let config = RotationConfig::builder().build();

    // Check that defaults are sensible
    assert!(config.max_file_size > 0);
    assert!(config.max_backups > 0);
}

#[test]
fn test_rotation_config_custom_values() {
    let config = RotationConfig::builder()
        .max_file_size(1024 * 1024) // 1MB
        .max_backups(5)
        .compress_rotated(true)
        .retention_days(30)
        .build();

    assert_eq!(config.max_file_size, 1024 * 1024);
    assert_eq!(config.max_backups, 5);
    assert!(config.compress_rotated);
    assert_eq!(config.retention_days, Some(30));
}

// ============================================================================
// Log Format Tests
// ============================================================================

#[test]
fn test_log_format_default_is_human_readable() {
    let format = LogFormat::default();
    assert!(matches!(format, LogFormat::HumanReadable));
}

#[test]
fn test_log_format_jsonlines_available() {
    let format = LogFormat::JsonLines;
    assert!(matches!(format, LogFormat::JsonLines));
}

// ============================================================================
// Event Formatting Tests
// ============================================================================

#[test]
fn test_event_can_be_serialized_to_json() {
    let event = Event::new(EventType::Info, "Test message");

    // Event should be serializable (this is required for JSONL format)
    let json = serde_json::to_string(&event);
    assert!(json.is_ok(), "Event should serialize to JSON");

    let json_str = json.expect("serialization succeeded");
    assert!(json_str.contains("Test message"));
    assert!(json_str.contains("Info") || json_str.contains("info"));
}

#[test]
fn test_event_json_contains_all_fields() {
    let event = Event::new(EventType::Warning, "Warning message");
    let json = serde_json::to_string(&event).expect("serialization should succeed");

    // Essential fields should be present
    assert!(json.contains("message"));
    assert!(json.contains("Warning message"));
    assert!(json.contains("timestamp") || json.contains("time"));
    assert!(json.contains("id"));
}

// ============================================================================
// Query Structure Tests
// ============================================================================

#[test]
fn test_audit_query_default() {
    let query = AuditQuery::default();

    // Default query should not filter anything
    assert!(query.min_severity.is_none());
    assert!(query.event_types.is_none());
    assert!(!query.security_relevant_only);
}

#[test]
fn test_audit_query_with_severity_filter() {
    let query = AuditQuery {
        min_severity: Some(Severity::Warning),
        ..Default::default()
    };

    assert_eq!(query.min_severity, Some(Severity::Warning));
}

#[test]
fn test_audit_query_with_pagination() {
    let query = AuditQuery {
        limit: Some(100),
        offset: Some(50),
        ..Default::default()
    };

    assert_eq!(query.limit, Some(100));
    assert_eq!(query.offset, Some(50));
}

#[test]
fn test_audit_query_time_range() {
    use chrono::{Duration, Utc};

    let now = Utc::now();
    let one_hour_ago = now - Duration::hours(1);

    let query = AuditQuery {
        since: Some(one_hour_ago),
        until: Some(now),
        ..Default::default()
    };

    assert!(query.since.is_some());
    assert!(query.until.is_some());
}

// ============================================================================
// Integration Tests (require filesystem)
// ============================================================================

// Note: Full FileWriter integration tests with actual file I/O are in the
// unit tests within the observe module. These tests focus on the public API
// contract and type safety.

#[test]
fn test_log_directory_and_filename_composition() {
    let (_dir, path) = temp_log_dir();
    let path_str = path.to_str().expect("valid UTF-8");

    let log_dir = LogDirectory::new(path_str).expect("valid directory");
    let filename = LogFilename::new("test.log").expect("valid filename");

    // These should be usable together
    let full_path = log_dir.as_path().join(filename.as_str());
    assert!(full_path.ends_with("test.log"));
}
