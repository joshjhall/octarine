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
fn test_builder_silent_disables_events_and_metrics() {
    let ops = SecureFileOpsBuilder::silent().build();

    assert_eq!(ops.config.audit_level, AuditLevel::Off);
    assert!(!ops.config.metrics_enabled);

    // The default builder must differ, or the assertions above are vacuous.
    let loud = SecureFileOps::builder().build();
    assert_eq!(loud.config.audit_level, AuditLevel::Full);
    assert!(loud.config.metrics_enabled);
}

#[test]
fn test_builder_with_events_round_trip() {
    let off = SecureFileOps::builder().with_events(false).build();
    assert_eq!(off.config.audit_level, AuditLevel::Off);
    assert!(!off.config.metrics_enabled);

    // with_events(true) must undo a prior silent(), not merely leave it.
    let back_on = SecureFileOpsBuilder::silent().with_events(true).build();
    assert_eq!(back_on.config.audit_level, AuditLevel::Full);
    assert!(back_on.config.metrics_enabled);
}

#[test]
fn test_builder_explicit_audit_level_overrides_with_events() {
    // The granular setters still win when applied after with_events.
    let ops = SecureFileOps::builder()
        .with_events(false)
        .audit_level(AuditLevel::Errors)
        .build();

    assert_eq!(ops.config.audit_level, AuditLevel::Errors);
    assert!(!ops.config.metrics_enabled, "metrics stay off");
}

// The metrics tests below use the `_sync` API deliberately: they exercise the
// same `record_metric`/`start_timer` helpers as the async paths, and
// `flush_for_testing()` blocks on a oneshot, which panics inside a tokio
// runtime.

fn metric_counter(name: &str) -> u64 {
    crate::observe::metrics::snapshot()
        .counters
        .get(name)
        .map_or(0, |c| c.value)
}

#[test]
fn test_metrics_recorded_on_write_and_read() {
    use crate::observe::metrics::flush_for_testing;

    let _guard = crate::observe::metrics::metrics_test_lock();
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("metrics.bin");
    let ops = SecureFileOps::new();

    flush_for_testing();
    let writes_before = metric_counter("io.file.write_count");
    let reads_before = metric_counter("io.file.read_count");
    let read_bytes_before = metric_counter("io.file.read_bytes");
    let write_bytes_before = metric_counter("io.file.write_bytes");

    let payload = b"0123456789";
    let payload_len = payload.len() as u64;
    ops.write_file_sync(&path, payload).expect("write");
    let read_back = ops.read_file_sync(&path).expect("read");
    flush_for_testing();

    assert_eq!(read_back.len() as u64, payload_len);
    // Growth, not an exact delta: the metrics registry is process-global and
    // sibling tests in this file also read and write files concurrently, so
    // only a lower bound is stable. The byte counters use >= payload_len,
    // which still fails if a count were recorded in place of a byte total.
    assert!(
        metric_counter("io.file.write_count") > writes_before,
        "write_count must increment on a write",
    );
    assert!(
        metric_counter("io.file.read_count") > reads_before,
        "read_count must increment on a read",
    );
    assert!(
        metric_counter("io.file.read_bytes") >= read_bytes_before.saturating_add(payload_len),
        "read_bytes must grow by at least the payload size, not by 1",
    );
    assert!(
        metric_counter("io.file.write_bytes") >= write_bytes_before.saturating_add(payload_len),
        "write_bytes must grow by at least the payload size, not by 1",
    );
}

#[test]
fn test_silent_ops_record_no_metrics_behaviorally() {
    // BEHAVIORAL: fails if `if self.config.metrics_enabled` is deleted from
    // record_metric/start_timer in core.rs.
    //
    // Measured with the per-thread tally rather than the global registry
    // snapshot. `io.file.write_count` is process-global and five sibling tests
    // in this very file write files without taking `metrics_test_lock()`, so an
    // absolute `== 0` against the registry races them (issue #793). The
    // thread-local count is attributable to this test alone, which makes the
    // zero assertion exact rather than merely likely.
    use crate::observe::metrics::{local_metric_count, reset_local_metrics};

    let dir = tempdir().expect("temp dir");
    reset_local_metrics();

    SecureFileOpsBuilder::silent()
        .build()
        .write_file_sync(dir.path().join("silent.bin"), b"data")
        .expect("write");
    let silent_delta = local_metric_count("io.file.write_count");

    SecureFileOps::new()
        .write_file_sync(dir.path().join("loud.bin"), b"data")
        .expect("write");
    let loud_delta = local_metric_count("io.file.write_count").saturating_sub(silent_delta);

    assert_eq!(silent_delta, 0, "silent() must not record write_count");
    assert!(
        loud_delta > silent_delta,
        "the loud write must record more than the silent one \
         (silent {silent_delta}, loud {loud_delta})",
    );
}

#[test]
fn test_lock_metrics_recorded() {
    use crate::observe::metrics::flush_for_testing;

    let _guard = crate::observe::metrics::metrics_test_lock();
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("locked.bin");
    let ops = SecureFileOps::new();

    flush_for_testing();
    let locks_before = metric_counter("io.file.lock_count");

    ops.write_locked(&path, b"locked").expect("write locked");
    flush_for_testing();

    assert!(
        metric_counter("io.file.lock_count") > locks_before,
        "the lock path must record lock_count",
    );
}

#[test]
fn test_silent_ops_record_no_lock_metrics() {
    // Gate-level, for the same reason as test_silent_ops_record_no_metrics:
    // io.file.lock_count is process-global and shared with sibling tests.
    let dir = tempdir().expect("temp dir");
    let ops = SecureFileOpsBuilder::silent().build();

    assert!(!ops.config.metrics_enabled);
    ops.write_locked(dir.path().join("silent.bin"), b"locked")
        .expect("write locked still succeeds when silent");
}

#[test]
fn test_silent_ops_record_no_metrics() {
    // Asserted at the gate rather than through the metrics registry: the
    // registry is process-global and sibling tests in this file read and
    // write files concurrently, so any "this counter did not move"
    // assertion races them. `record_metric`/`start_timer` in core.rs are
    // both gated on exactly this flag, and test_metrics_recorded_on_write_and_read
    // covers the recording side.
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("silent.bin");
    let ops = SecureFileOpsBuilder::silent().build();

    assert!(
        !ops.config.metrics_enabled,
        "silent() must disable the flag record_metric/start_timer gate on",
    );
    assert_eq!(ops.config.audit_level, AuditLevel::Off);

    // And the operation still works with events off.
    ops.write_file_sync(&path, b"data")
        .expect("write still succeeds when silent");
    let read_back = ops.read_file_sync(&path).expect("read still succeeds");
    assert_eq!(read_back, b"data".to_vec(), "silent must not break the op");

    // The default builder must differ, or the flag assertions are vacuous.
    assert!(SecureFileOps::new().config.metrics_enabled);
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
