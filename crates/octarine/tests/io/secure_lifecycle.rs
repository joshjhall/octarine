#![allow(clippy::panic, clippy::expect_used)]

use octarine::io::{
    DeleteMethod, SecureDelete, SecureTempFile, detect_file_type_sync, validate_image_sync,
    validate_not_dangerous_sync,
};
use tempfile::tempdir;

/// Full lifecycle: create temp file → write PNG bytes → detect type → validate image → drop.
#[test]
fn test_temp_file_write_detect_validate_drop() {
    let dir = tempdir().expect("create temp dir");
    let png_header: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    let path = {
        let mut temp = SecureTempFile::builder()
            .prefix("img-")
            .suffix(".png")
            .in_dir(dir.path())
            .build_sync()
            .expect("create temp file");

        temp.write_all(&png_header).expect("write PNG bytes");
        temp.sync().expect("sync to disk");

        let path = temp.path().to_path_buf();

        // Detect type while file is still alive
        let result = detect_file_type_sync(&path).expect("detect");
        assert_eq!(
            result.file_type,
            Some(octarine::io::MagicFileType::Png),
            "Should detect PNG from magic bytes"
        );

        // Validate it's an image
        validate_image_sync(&path).expect("should validate as image");

        // Validate it's not dangerous
        validate_not_dangerous_sync(&path).expect("PNG should not be dangerous");

        path
    };

    // After drop, file should be cleaned up
    assert!(!path.exists(), "Temp file should be deleted after drop");
}

/// Async lifecycle: create → write → detect → validate → explicit delete.
#[tokio::test]
async fn test_async_temp_file_lifecycle() {
    let dir = tempdir().expect("create temp dir");
    let jpeg_header: [u8; 4] = [0xFF, 0xD8, 0xFF, 0xE0];

    let mut temp = SecureTempFile::builder()
        .prefix("photo-")
        .suffix(".jpg")
        .in_dir(dir.path())
        .build()
        .await
        .expect("create async temp file");

    temp.write_all(&jpeg_header).expect("write JPEG bytes");
    temp.sync().expect("sync");

    let path = temp.path().to_path_buf();

    // Detect type
    let result = octarine::io::detect_file_type(path.clone())
        .await
        .expect("detect async");
    assert_eq!(result.file_type, Some(octarine::io::MagicFileType::Jpeg));

    // Validate image
    octarine::io::validate_image(path.clone())
        .await
        .expect("validate async");

    // Explicit async delete
    temp.delete().await.expect("async delete");
    assert!(!path.exists());
}

/// SecureTempFile with secure_delete enabled → verify file is gone after drop.
#[test]
fn test_secure_delete_on_temp_file() {
    let dir = tempdir().expect("create temp dir");

    let path = {
        let mut temp = SecureTempFile::builder()
            .in_dir(dir.path())
            .secure_delete(true)
            .build_sync()
            .expect("create with secure delete");

        assert!(temp.secure_delete_enabled());

        temp.write_all(b"sensitive credentials").expect("write");
        temp.sync().expect("sync");
        temp.path().to_path_buf()
    };

    assert!(!path.exists(), "Securely deleted file should not exist");
}

/// SecureDelete with DoD method on a file >128KB.
#[test]
fn test_dod_delete_large_file() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("large_classified.bin");

    // Create 256KB file
    let data = vec![0xABu8; 256 * 1024];
    std::fs::write(&path, &data).expect("write large file");

    let result = SecureDelete::new_sync(&path)
        .expect("create secure delete")
        .method(DeleteMethod::Dod522022M)
        .verify(true)
        .execute_sync()
        .expect("execute DoD delete");

    assert!(!path.exists());
    assert_eq!(result.method, DeleteMethod::Dod522022M);
    assert_eq!(result.passes, 3);
    assert_eq!(result.bytes_overwritten, 256 * 1024);
    assert!(result.verified);
}

/// Async secure delete with NIST method.
#[tokio::test]
async fn test_async_secure_delete_nist() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("nist_delete.txt");

    std::fs::write(&path, b"classified info").expect("write file");

    let result = octarine::io::secure_delete(&path)
        .await
        .expect("async secure delete");

    assert!(!path.exists());
    assert_eq!(result.method, DeleteMethod::Nist80088);
}

/// SecureDelete on nonexistent file returns error, not panic.
#[test]
fn test_secure_delete_nonexistent_file() {
    let result = SecureDelete::new_sync("/tmp/nonexistent_file_12345.txt");
    assert!(result.is_err(), "Should error on nonexistent file");
}
