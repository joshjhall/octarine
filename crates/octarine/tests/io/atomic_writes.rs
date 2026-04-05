#![allow(clippy::panic, clippy::expect_used)]

use octarine::io::{FileMode, SecureFileOps, WriteOptions, write_atomic};
use tempfile::tempdir;

/// Write atomic → read back via SecureFileOps → verify content round-trips.
#[test]
fn test_atomic_write_then_ops_read_roundtrip() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("roundtrip.txt");

    let data = b"integration test data";
    write_atomic(&path, data, WriteOptions::default()).expect("atomic write");

    let ops = SecureFileOps::new();
    let contents = ops.read_file_sync(&path).expect("read via SecureFileOps");
    assert_eq!(contents, data);
}

/// Write with for_secrets() options → verify 0600 permissions on Unix.
#[cfg(unix)]
#[test]
fn test_atomic_write_secrets_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("secret.key");

    write_atomic(&path, b"supersecret", WriteOptions::for_secrets()).expect("atomic write secrets");

    let metadata = std::fs::metadata(&path).expect("metadata");
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "Secrets should have 0600 permissions");

    // Verify content is also correct
    let contents = std::fs::read(&path).expect("read");
    assert_eq!(contents, b"supersecret");
}

/// Write atomic → set_mode → verify the new mode takes effect.
#[cfg(unix)]
#[test]
fn test_atomic_write_then_set_mode() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("mode_change.txt");

    write_atomic(&path, b"data", WriteOptions::default()).expect("atomic write");
    octarine::io::set_mode(&path, FileMode::PRIVATE).expect("set mode");

    let mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

/// Overwriting an existing file via atomic write preserves atomicity.
#[test]
fn test_atomic_write_overwrites_existing() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("overwrite.txt");

    write_atomic(&path, b"original", WriteOptions::default()).expect("first write");
    write_atomic(&path, b"replacement", WriteOptions::default()).expect("second write");

    let contents = std::fs::read_to_string(&path).expect("read");
    assert_eq!(contents, "replacement");
}

/// Write with for_logs() options works correctly.
#[test]
fn test_atomic_write_for_logs() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("app.log");

    write_atomic(&path, b"log entry\n", WriteOptions::for_logs()).expect("atomic write logs");

    let contents = std::fs::read_to_string(&path).expect("read");
    assert_eq!(contents, "log entry\n");
}
