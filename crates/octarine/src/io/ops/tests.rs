//! Unit tests for `SecureFileOps`
//!
//! Covers async + sync read/write/exists, builder configuration, config
//! presets, magic-byte validation, locked operations, and `set_mode`.

#![allow(clippy::panic, clippy::expect_used)]

use super::*;
use crate::io::MagicFileType;
use crate::primitives::io::file::FileMode;
use tempfile::tempdir;

#[test]
fn test_secure_file_ops_new() {
    let ops = SecureFileOps::new();
    assert_eq!(ops.config.audit_level, AuditLevel::Full);
    assert!(ops.config.metrics_enabled);
}

#[test]
fn test_write_and_read_sync() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("test.txt");

    let ops = SecureFileOps::new();
    ops.write_file_sync(&path, b"hello world").expect("write");

    let contents = ops.read_file_sync(&path).expect("read");
    assert_eq!(contents, b"hello world");
}

#[tokio::test]
async fn test_write_and_read_async() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("test_async.txt");

    let ops = SecureFileOps::new();
    ops.write_file(path.clone(), b"hello async".to_vec())
        .await
        .expect("write");

    let contents = ops.read_file(path).await.expect("read");
    assert_eq!(contents, b"hello async");
}

#[test]
fn test_write_and_read_string_sync() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("test.txt");

    let ops = SecureFileOps::new();
    ops.write_file_string_sync(&path, "hello string")
        .expect("write");

    let contents = ops.read_file_string_sync(&path).expect("read");
    assert_eq!(contents, "hello string");
}

#[test]
fn test_exists_sync() {
    let dir = tempdir().expect("create temp dir");
    let existing = dir.path().join("exists.txt");
    let missing = dir.path().join("missing.txt");

    std::fs::write(&existing, b"test").expect("create file");

    let ops = SecureFileOps::new();
    assert!(ops.exists_sync(&existing));
    assert!(!ops.exists_sync(&missing));
}

#[tokio::test]
async fn test_exists_async() {
    let dir = tempdir().expect("create temp dir");
    let existing = dir.path().join("exists_async.txt");
    let missing = dir.path().join("missing_async.txt");

    std::fs::write(&existing, b"test").expect("create file");

    let ops = SecureFileOps::new();
    assert!(ops.exists(existing).await.expect("exists"));
    assert!(!ops.exists(missing).await.expect("exists"));
}

#[test]
fn test_file_size_sync() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("sized.txt");

    std::fs::write(&path, b"12345").expect("create file");

    let ops = SecureFileOps::new();
    let size = ops.file_size_sync(&path).expect("get size");
    assert_eq!(size, 5);
}

#[test]
fn test_builder() {
    let ops = SecureFileOps::builder()
        .audit_level(AuditLevel::Errors)
        .metrics(false)
        .validate_magic(true)
        .build();

    assert_eq!(ops.config.audit_level, AuditLevel::Errors);
    assert!(!ops.config.metrics_enabled);
    assert!(ops.config.validate_magic);
}

#[test]
fn test_config_presets() {
    let secure = SecureFileOpsConfig::secure();
    assert!(secure.validate_magic);
    assert_eq!(secure.audit_level, AuditLevel::Full);

    let dev = SecureFileOpsConfig::development();
    assert_eq!(dev.audit_level, AuditLevel::Debug);

    let perf = SecureFileOpsConfig::performance();
    assert!(!perf.metrics_enabled);
}

#[test]
fn test_write_secrets_sync() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("secret.txt");

    let ops = SecureFileOps::new();
    ops.write_secrets_sync(&path, b"secret data")
        .expect("write secrets");

    let contents = ops.read_file_sync(&path).expect("read");
    assert_eq!(contents, b"secret data");

    // On Unix, check permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn test_locked_read_write() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("locked.txt");

    let ops = SecureFileOps::new();

    // Write with lock
    ops.write_locked(&path, b"locked data")
        .expect("write locked");

    // Read with lock
    let contents = ops.read_locked(&path).expect("read locked");
    assert_eq!(contents, b"locked data");
}

#[test]
fn test_detect_type_sync() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("test.png");

    // Write PNG magic bytes
    std::fs::write(&path, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).expect("write png");

    let ops = SecureFileOps::new();
    let result = ops.detect_type_sync(&path).expect("detect");
    assert_eq!(result.file_type, Some(MagicFileType::Png));
}

#[test]
fn test_read_validated_image_sync() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("image.png");

    // Write PNG magic bytes
    std::fs::write(&path, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).expect("write png");

    let ops = SecureFileOps::new();
    let data = ops.read_validated_image_sync(&path).expect("read image");
    assert_eq!(data.len(), 8);
}

#[test]
fn test_read_validated_image_rejects_non_image() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("fake.png");

    // Write ELF magic (not an image)
    std::fs::write(&path, [0x7F, 0x45, 0x4C, 0x46]).expect("write elf");

    let ops = SecureFileOps::new();
    let result = ops.read_validated_image_sync(&path);
    assert!(result.is_err());
}

#[test]
fn test_read_safe_rejects_dangerous() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("script.sh");

    // Write shebang
    std::fs::write(&path, b"#!/bin/bash\necho hello").expect("write script");

    let ops = SecureFileOps::new();
    let result = ops.read_safe_sync(&path);
    assert!(result.is_err());
}

#[test]
fn test_set_mode() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("mode.txt");

    std::fs::write(&path, b"test").expect("create file");

    let ops = SecureFileOps::new();
    ops.set_mode(&path, FileMode::PRIVATE).expect("set mode");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
