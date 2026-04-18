#![allow(clippy::panic, clippy::expect_used)]

use octarine::io::{
    AuditLevel, FileMode, MagicFileType, SecureFileOps, SecureFileOpsConfig, WriteOptions,
};
use tempfile::tempdir;

// =========================================================================
// Config presets end-to-end
// =========================================================================

/// SecureFileOps::secure() preset → write secrets → read back → verify permissions.
#[cfg(unix)]
#[test]
fn test_secure_preset_write_secrets_roundtrip() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("api_key.pem");

    let ops = SecureFileOps::with_config(SecureFileOpsConfig::secure());
    ops.write_secrets_sync(&path, b"super-secret-api-key-value-12345")
        .expect("write secrets");

    let contents = ops.read_file_sync(&path).expect("read");
    assert_eq!(contents, b"super-secret-api-key-value-12345");

    let mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "Secrets should have 0600 permissions");
}

/// Development preset still correctly reads and writes.
#[test]
fn test_development_preset_roundtrip() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("debug.log");

    let ops = SecureFileOps::with_config(SecureFileOpsConfig::development());
    ops.write_file_string_sync(&path, "debug output")
        .expect("write");

    let contents = ops.read_file_string_sync(&path).expect("read string");
    assert_eq!(contents, "debug output");
}

/// Performance preset (minimal logging) still works correctly.
#[test]
fn test_performance_preset_roundtrip() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("data.bin");

    let ops = SecureFileOps::with_config(SecureFileOpsConfig::performance());
    ops.write_file_sync(&path, b"\x00\x01\x02\x03")
        .expect("write");

    let contents = ops.read_file_sync(&path).expect("read");
    assert_eq!(contents, b"\x00\x01\x02\x03");
}

// =========================================================================
// Locked read/write round-trip
// =========================================================================

/// Write with lock → read with lock → content matches.
#[test]
fn test_locked_write_then_locked_read() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("locked_data.txt");

    let ops = SecureFileOps::new();
    ops.write_locked(&path, b"locked content")
        .expect("write locked");

    let contents = ops.read_locked(&path).expect("read locked");
    assert_eq!(contents, b"locked content");
}

/// Overwrite via locked write replaces content.
#[test]
fn test_locked_write_overwrites() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("overwrite_locked.txt");

    let ops = SecureFileOps::new();
    ops.write_locked(&path, b"first").expect("first write");
    ops.write_locked(&path, b"second").expect("second write");

    let contents = ops.read_locked(&path).expect("read");
    assert_eq!(contents, b"second");
}

// =========================================================================
// Magic validation via SecureFileOps
// =========================================================================

/// read_validated_image accepts PNG, rejects ELF.
#[test]
fn test_read_validated_image_accepts_and_rejects() {
    let dir = tempdir().expect("create temp dir");
    let png_path = dir.path().join("valid.png");
    let elf_path = dir.path().join("fake.png");

    std::fs::write(&png_path, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).expect("write PNG");
    std::fs::write(&elf_path, [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01]).expect("write ELF");

    let ops = SecureFileOps::new();

    let data = ops.read_validated_image_sync(&png_path).expect("read PNG");
    assert_eq!(data.len(), 8);

    assert!(
        ops.read_validated_image_sync(&elf_path).is_err(),
        "ELF should not pass image validation"
    );
}

/// read_safe accepts PNG, rejects script.
#[test]
fn test_read_safe_accepts_image_rejects_script() {
    let dir = tempdir().expect("create temp dir");
    let png_path = dir.path().join("safe.png");
    let script_path = dir.path().join("dangerous.sh");

    std::fs::write(&png_path, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).expect("write PNG");
    std::fs::write(&script_path, b"#!/bin/bash\necho pwned").expect("write script");

    let ops = SecureFileOps::new();

    ops.read_safe_sync(&png_path).expect("PNG should be safe");
    assert!(
        ops.read_safe_sync(&script_path).is_err(),
        "Script should be rejected as dangerous"
    );
}

/// detect_type via SecureFileOps returns correct MagicFileType.
#[test]
fn test_detect_type_via_ops() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("archive.zip");

    std::fs::write(&path, [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00]).expect("write ZIP");

    let ops = SecureFileOps::new();
    let result = ops.detect_type_sync(&path).expect("detect");
    assert_eq!(result.file_type, Some(MagicFileType::ZipArchive));
}

// =========================================================================
// Builder configuration
// =========================================================================

/// Builder with custom audit level and write options.
#[test]
fn test_builder_custom_config() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("custom.txt");

    let ops = SecureFileOps::builder()
        .audit_level(AuditLevel::Errors)
        .metrics(false)
        .default_write_options(WriteOptions::for_config())
        .build();

    ops.write_file_sync(&path, b"config data").expect("write");

    let contents = ops.read_file_sync(&path).expect("read");
    assert_eq!(contents, b"config data");
}

// =========================================================================
// Async operations
// =========================================================================

/// Async write → read round-trip via SecureFileOps.
#[tokio::test]
async fn test_async_write_read_roundtrip() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("async_roundtrip.txt");

    let ops = SecureFileOps::new();
    ops.write_file(path.clone(), b"async data".to_vec())
        .await
        .expect("async write");

    let contents = ops.read_file(path).await.expect("async read");
    assert_eq!(contents, b"async data");
}

/// Async exists check.
#[tokio::test]
async fn test_async_exists() {
    let dir = tempdir().expect("create temp dir");
    let existing = dir.path().join("exists.txt");
    let missing = dir.path().join("missing.txt");

    std::fs::write(&existing, b"yes").expect("create file");

    let ops = SecureFileOps::new();
    assert!(ops.exists(existing).await.expect("exists"));
    assert!(!ops.exists(missing).await.expect("not exists"));
}

/// Async read_file_string returns UTF-8 content.
#[tokio::test]
async fn test_async_read_file_string() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("async_string.txt");

    let ops = SecureFileOps::new();
    ops.write_file(path.clone(), b"hello async string".to_vec())
        .await
        .expect("async write");

    let contents = ops.read_file_string(path).await.expect("async read string");
    assert_eq!(contents, "hello async string");
}

/// Async read_file_string rejects non-UTF-8 content.
#[tokio::test]
async fn test_async_read_file_string_rejects_invalid_utf8() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("invalid_utf8.bin");

    std::fs::write(&path, [0xFF, 0xFE, 0x00, 0x80]).expect("write invalid UTF-8");

    let ops = SecureFileOps::new();
    assert!(
        ops.read_file_string(path).await.is_err(),
        "Non-UTF-8 should be rejected"
    );
}

/// Async read_validated_image accepts PNG.
#[tokio::test]
async fn test_async_read_validated_image_accepts_png() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("async_valid.png");

    std::fs::write(&path, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).expect("write PNG");

    let ops = SecureFileOps::new();
    let data = ops
        .read_validated_image(path)
        .await
        .expect("async read PNG");
    assert_eq!(data.len(), 8);
}

/// Async read_validated_image rejects ELF disguised as image.
#[tokio::test]
async fn test_async_read_validated_image_rejects_elf() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("async_fake.png");

    std::fs::write(&path, [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01]).expect("write ELF");

    let ops = SecureFileOps::new();
    assert!(
        ops.read_validated_image(path).await.is_err(),
        "ELF should not pass async image validation"
    );
}

/// Async read_safe accepts PNG.
#[tokio::test]
async fn test_async_read_safe_accepts_image() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("async_safe.png");

    std::fs::write(&path, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).expect("write PNG");

    let ops = SecureFileOps::new();
    ops.read_safe(path).await.expect("PNG should be safe");
}

/// Async read_safe rejects script.
#[tokio::test]
async fn test_async_read_safe_rejects_script() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("async_dangerous.sh");

    std::fs::write(&path, b"#!/bin/bash\necho pwned").expect("write script");

    let ops = SecureFileOps::new();
    assert!(
        ops.read_safe(path).await.is_err(),
        "Script should be rejected as dangerous"
    );
}

/// Async write_file_with_options writes with custom options.
#[tokio::test]
async fn test_async_write_file_with_options() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("async_options.txt");

    let ops = SecureFileOps::new();
    ops.write_file_with_options(
        path.clone(),
        b"config data".to_vec(),
        WriteOptions::for_config(),
    )
    .await
    .expect("async write with options");

    let contents = ops.read_file(path).await.expect("async read");
    assert_eq!(contents, b"config data");
}

/// Async write_file_string writes string content.
#[tokio::test]
async fn test_async_write_file_string() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("async_string_write.txt");

    let ops = SecureFileOps::new();
    ops.write_file_string(path.clone(), "async string content".to_string())
        .await
        .expect("async write string");

    let contents = ops.read_file_string(path).await.expect("async read string");
    assert_eq!(contents, "async string content");
}

/// Async write_secrets writes with 0600 permissions.
#[cfg(unix)]
#[tokio::test]
async fn test_async_write_secrets() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("async_secret.pem");

    let ops = SecureFileOps::new();
    ops.write_secrets(path.clone(), b"async-secret-key".to_vec())
        .await
        .expect("async write secrets");

    let contents = ops.read_file(path.clone()).await.expect("async read");
    assert_eq!(contents, b"async-secret-key");

    let mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "Secrets should have 0600 permissions");
}

/// Async detect_type identifies file format.
#[tokio::test]
async fn test_async_detect_type() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("async_archive.zip");

    std::fs::write(&path, [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00]).expect("write ZIP");

    let ops = SecureFileOps::new();
    let result = ops.detect_type(path).await.expect("async detect");
    assert_eq!(result.file_type, Some(MagicFileType::ZipArchive));
}

/// file_size returns correct size.
#[test]
fn test_file_size() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("sized.bin");

    std::fs::write(&path, vec![0u8; 1024]).expect("write 1KB file");

    let ops = SecureFileOps::new();
    let size = ops.file_size_sync(&path).expect("get size");
    assert_eq!(size, 1024);
}

/// Async file_size returns correct size.
#[tokio::test]
async fn test_async_file_size() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("sized_async.bin");

    std::fs::write(&path, vec![0u8; 2048]).expect("write 2KB file");

    let ops = SecureFileOps::new();
    let size = ops.file_size(path).await.expect("async file size");
    assert_eq!(size, 2048);
}

/// set_mode via SecureFileOps changes permissions.
#[cfg(unix)]
#[test]
fn test_set_mode_via_ops() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("mode_test.txt");

    std::fs::write(&path, b"test").expect("create file");

    let ops = SecureFileOps::new();
    ops.set_mode(&path, FileMode::PRIVATE).expect("set mode");

    let mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}
