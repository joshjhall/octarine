//! File type validation with observability
//!
//! Validation functions that enforce file type policies with audit trails.
//! Follows async-first design: async functions by default, `_sync` suffix for blocking.

use std::path::Path;

use crate::observe::{self, Problem};
use crate::primitives::io::file as prim;

use super::detection::{
    MagicFileType, MagicResult, detect_file_type, detect_file_type_sync, read_magic_bytes,
    read_magic_bytes_sync,
};

// ============================================================================
// Validation Functions (Async - Default)
// ============================================================================

/// Validate that a file is an image (async)
///
/// Returns an error if the file is not detected as an image type.
/// Useful for validating user uploads.
///
/// # Errors
///
/// Returns `Problem::Validation` if not an image, or `Problem::Io` if unreadable.
pub async fn validate_image(
    path: impl AsRef<Path> + Send + 'static,
) -> Result<MagicResult, Problem> {
    let path = path.as_ref().to_path_buf();
    let path_str = path.display().to_string();
    let result = detect_file_type(path.clone()).await?;

    if !prim::is_image_magic(&read_magic_bytes(path).await?) {
        observe::warn(
            "io.magic.validate",
            format!(
                "File {} failed image validation (detected: {:?})",
                path_str, result.file_type
            ),
        );
        return Err(Problem::validation(format!(
            "File is not an image: {}",
            path_str
        )));
    }

    observe::debug(
        "io.magic.validate",
        format!("File {} passed image validation", path_str),
    );
    Ok(result)
}

/// Validate that a file is not dangerous (async)
///
/// Returns an error if the file appears to be an executable, archive, or script.
/// Use this to reject potentially malicious uploads.
///
/// # Errors
///
/// Returns `Problem::Validation` if dangerous, or `Problem::Io` if unreadable.
pub async fn validate_not_dangerous(
    path: impl AsRef<Path> + Send + 'static,
) -> Result<MagicResult, Problem> {
    let path = path.as_ref().to_path_buf();
    let path_str = path.display().to_string();
    let header = read_magic_bytes(path).await?;
    let result = prim::detect_magic(&header);

    if prim::is_dangerous_magic(&header) {
        observe::warn(
            "io.magic.validate",
            format!(
                "File {} detected as dangerous type: {:?}",
                path_str, result.file_type
            ),
        );
        return Err(Problem::validation(format!(
            "Dangerous file type detected: {} ({:?})",
            path_str, result.file_type
        )));
    }

    observe::debug(
        "io.magic.validate",
        format!("File {} passed safety validation", path_str),
    );
    Ok(result)
}

/// Validate that a file matches an expected type (async)
///
/// Returns an error if the detected type doesn't match the expected type.
///
/// # Errors
///
/// Returns `Problem::Validation` if type doesn't match, or `Problem::Io` if unreadable.
pub async fn validate_file_type(
    path: impl AsRef<Path> + Send + 'static,
    expected: MagicFileType,
) -> Result<MagicResult, Problem> {
    let path = path.as_ref().to_path_buf();
    let path_str = path.display().to_string();
    let result = detect_file_type(path).await?;

    match result.file_type {
        Some(actual) if actual == expected => {
            observe::debug(
                "io.magic.validate",
                format!("File {} matches expected type {:?}", path_str, expected),
            );
            Ok(result)
        }
        actual => {
            observe::warn(
                "io.magic.validate",
                format!(
                    "File {} type mismatch: expected {:?}, got {:?}",
                    path_str, expected, actual
                ),
            );
            Err(Problem::validation(format!(
                "File type mismatch for {}: expected {:?}, detected {:?}",
                path_str, expected, actual
            )))
        }
    }
}

/// Validate that file extension matches detected magic bytes (async)
///
/// Returns an error if the file extension doesn't match the detected content type.
/// This catches spoofed files (e.g., an EXE renamed to .jpg).
///
/// # Errors
///
/// Returns `Problem::Validation` if mismatch detected, or `Problem::Io` if unreadable.
pub async fn validate_extension_matches(
    path: impl AsRef<Path> + Send + 'static,
) -> Result<MagicResult, Problem> {
    let path = path.as_ref().to_path_buf();
    let path_str = path.display().to_string();
    let result = detect_file_type(path.clone()).await?;

    // If we couldn't detect the type, we can't validate
    let Some(detected_type) = result.file_type else {
        observe::debug(
            "io.magic.validate",
            format!(
                "File {} has unknown type, skipping extension validation",
                path_str
            ),
        );
        return Ok(result);
    };

    // Get the file extension
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase());

    let Some(ext) = extension else {
        // No extension to validate against
        observe::debug(
            "io.magic.validate",
            format!("File {} has no extension, skipping validation", path_str),
        );
        return Ok(result);
    };

    // Get expected extension for detected type
    let expected_ext = detected_type.typical_extension();

    // Check for common extension aliases
    let ext_matches = extension_matches_type(&ext, detected_type, expected_ext);

    if !ext_matches {
        observe::warn(
            "io.magic.validate",
            format!(
                "File {} extension mismatch: .{} but detected as {} (expected .{})",
                path_str,
                ext,
                detected_type.mime_type(),
                expected_ext
            ),
        );
        return Err(Problem::validation(format!(
            "Extension mismatch for {}: .{} contains {} content",
            path_str,
            ext,
            detected_type.mime_type()
        )));
    }

    observe::debug(
        "io.magic.validate",
        format!("File {} extension matches content type", path_str),
    );
    Ok(result)
}

// ============================================================================
// Validation Functions (Sync - Explicit Opt-In)
// ============================================================================

/// Validate that a file is an image (sync, blocking)
///
/// **Warning**: This WILL block the current thread.
pub fn validate_image_sync(path: impl AsRef<Path>) -> Result<MagicResult, Problem> {
    let path = path.as_ref();
    let path_str = path.display().to_string();
    let result = detect_file_type_sync(path)?;

    if !prim::is_image_magic(&read_magic_bytes_sync(path)?) {
        observe::warn(
            "io.magic.validate",
            format!(
                "File {} failed image validation (detected: {:?})",
                path_str, result.file_type
            ),
        );
        return Err(Problem::validation(format!(
            "File is not an image: {}",
            path_str
        )));
    }

    observe::debug(
        "io.magic.validate",
        format!("File {} passed image validation", path_str),
    );
    Ok(result)
}

/// Validate that a file is not dangerous (sync, blocking)
///
/// **Warning**: This WILL block the current thread.
pub fn validate_not_dangerous_sync(path: impl AsRef<Path>) -> Result<MagicResult, Problem> {
    let path = path.as_ref();
    let path_str = path.display().to_string();
    let header = read_magic_bytes_sync(path)?;
    let result = prim::detect_magic(&header);

    if prim::is_dangerous_magic(&header) {
        observe::warn(
            "io.magic.validate",
            format!(
                "File {} detected as dangerous type: {:?}",
                path_str, result.file_type
            ),
        );
        return Err(Problem::validation(format!(
            "Dangerous file type detected: {} ({:?})",
            path_str, result.file_type
        )));
    }

    observe::debug(
        "io.magic.validate",
        format!("File {} passed safety validation", path_str),
    );
    Ok(result)
}

/// Validate that a file matches an expected type (sync, blocking)
///
/// **Warning**: This WILL block the current thread.
pub fn validate_file_type_sync(
    path: impl AsRef<Path>,
    expected: MagicFileType,
) -> Result<MagicResult, Problem> {
    let path = path.as_ref();
    let path_str = path.display().to_string();
    let result = detect_file_type_sync(path)?;

    match result.file_type {
        Some(actual) if actual == expected => {
            observe::debug(
                "io.magic.validate",
                format!("File {} matches expected type {:?}", path_str, expected),
            );
            Ok(result)
        }
        actual => {
            observe::warn(
                "io.magic.validate",
                format!(
                    "File {} type mismatch: expected {:?}, got {:?}",
                    path_str, expected, actual
                ),
            );
            Err(Problem::validation(format!(
                "File type mismatch for {}: expected {:?}, detected {:?}",
                path_str, expected, actual
            )))
        }
    }
}

/// Validate that file extension matches detected magic bytes (sync, blocking)
///
/// **Warning**: This WILL block the current thread.
pub fn validate_extension_matches_sync(path: impl AsRef<Path>) -> Result<MagicResult, Problem> {
    let path = path.as_ref();
    let path_str = path.display().to_string();
    let result = detect_file_type_sync(path)?;

    // If we couldn't detect the type, we can't validate
    let Some(detected_type) = result.file_type else {
        observe::debug(
            "io.magic.validate",
            format!(
                "File {} has unknown type, skipping extension validation",
                path_str
            ),
        );
        return Ok(result);
    };

    // Get the file extension
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase());

    let Some(ext) = extension else {
        // No extension to validate against
        observe::debug(
            "io.magic.validate",
            format!("File {} has no extension, skipping validation", path_str),
        );
        return Ok(result);
    };

    // Get expected extension for detected type
    let expected_ext = detected_type.typical_extension();

    // Check for common extension aliases
    let ext_matches = extension_matches_type(&ext, detected_type, expected_ext);

    if !ext_matches {
        observe::warn(
            "io.magic.validate",
            format!(
                "File {} extension mismatch: .{} but detected as {} (expected .{})",
                path_str,
                ext,
                detected_type.mime_type(),
                expected_ext
            ),
        );
        return Err(Problem::validation(format!(
            "Extension mismatch for {}: .{} contains {} content",
            path_str,
            ext,
            detected_type.mime_type()
        )));
    }

    observe::debug(
        "io.magic.validate",
        format!("File {} extension matches content type", path_str),
    );
    Ok(result)
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Check if extension matches expected type, handling common aliases
fn extension_matches_type(ext: &str, detected_type: MagicFileType, expected_ext: &str) -> bool {
    match detected_type {
        MagicFileType::Jpeg => ext == "jpg" || ext == "jpeg",
        MagicFileType::Tiff => ext == "tif" || ext == "tiff",
        MagicFileType::MachO | MagicFileType::MachOFat => {
            ext == "macho" || ext == "dylib" || ext == "so" || ext.is_empty()
        }
        MagicFileType::Elf => ext == "elf" || ext == "so" || ext == "o" || ext.is_empty(),
        MagicFileType::Pe => ext == "exe" || ext == "dll" || ext == "sys",
        MagicFileType::ZipArchive => {
            // ZIP-based formats
            ext == "zip"
                || ext == "docx"
                || ext == "xlsx"
                || ext == "pptx"
                || ext == "odt"
                || ext == "ods"
                || ext == "odp"
                || ext == "jar"
                || ext == "apk"
        }
        MagicFileType::Gzip => ext == "gz" || ext == "tgz",
        MagicFileType::Mkv => ext == "mkv" || ext == "webm",
        _ => ext == expected_ext,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    // ----------------------------------------
    // validate_image Tests (Sync)
    // ----------------------------------------

    #[test]
    fn test_validate_image_sync_success() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("valid.png");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            .expect("write");

        assert!(validate_image_sync(&path).is_ok());
    }

    #[test]
    fn test_validate_image_sync_failure_elf() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("fake.png");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00])
            .expect("write");

        assert!(validate_image_sync(&path).is_err());
    }

    #[test]
    fn test_validate_image_sync_failure_text() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("text.txt");

        let mut file = File::create(&path).expect("create file");
        file.write_all(b"Hello, world!").expect("write");

        assert!(validate_image_sync(&path).is_err());
    }

    // ----------------------------------------
    // validate_image Tests (Async)
    // ----------------------------------------

    #[tokio::test]
    async fn test_validate_image_async_success() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("valid_async.png");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            .expect("write");

        assert!(validate_image(path).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_image_async_failure() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("fake_async.png");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00])
            .expect("write");

        assert!(validate_image(path).await.is_err());
    }

    // ----------------------------------------
    // validate_not_dangerous Tests (Sync)
    // ----------------------------------------

    #[test]
    fn test_validate_not_dangerous_sync_success_image() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("safe.png");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            .expect("write");

        assert!(validate_not_dangerous_sync(&path).is_ok());
    }

    #[test]
    fn test_validate_not_dangerous_sync_failure_elf() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("dangerous");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00])
            .expect("write");

        assert!(validate_not_dangerous_sync(&path).is_err());
    }

    #[test]
    fn test_validate_not_dangerous_sync_failure_zip() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("archive.zip");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x50, 0x4B, 0x03, 0x04, 0x00, 0x00])
            .expect("write");

        assert!(validate_not_dangerous_sync(&path).is_err());
    }

    #[test]
    fn test_validate_not_dangerous_sync_failure_script() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("script.sh");

        let mut file = File::create(&path).expect("create file");
        file.write_all(b"#!/bin/bash\necho 'hello'").expect("write");

        assert!(validate_not_dangerous_sync(&path).is_err());
    }

    // ----------------------------------------
    // validate_not_dangerous Tests (Async)
    // ----------------------------------------

    #[tokio::test]
    async fn test_validate_not_dangerous_async_success() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("safe_async.png");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            .expect("write");

        assert!(validate_not_dangerous(path).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_not_dangerous_async_failure() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("dangerous_async");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00])
            .expect("write");

        assert!(validate_not_dangerous(path).await.is_err());
    }

    // ----------------------------------------
    // validate_file_type Tests (Sync)
    // ----------------------------------------

    #[test]
    fn test_validate_file_type_sync_success() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("doc.pdf");

        let mut file = File::create(&path).expect("create file");
        file.write_all(b"%PDF-1.4\n").expect("write");

        assert!(validate_file_type_sync(&path, MagicFileType::Pdf).is_ok());
    }

    #[test]
    fn test_validate_file_type_sync_mismatch() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("doc.pdf");

        let mut file = File::create(&path).expect("create file");
        file.write_all(b"%PDF-1.4\n").expect("write");

        assert!(validate_file_type_sync(&path, MagicFileType::Png).is_err());
    }

    // ----------------------------------------
    // validate_file_type Tests (Async)
    // ----------------------------------------

    #[tokio::test]
    async fn test_validate_file_type_async_success() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("doc_async.pdf");

        let mut file = File::create(&path).expect("create file");
        file.write_all(b"%PDF-1.4\n").expect("write");

        assert!(validate_file_type(path, MagicFileType::Pdf).await.is_ok());
    }

    // ----------------------------------------
    // validate_extension_matches Tests (Sync)
    // ----------------------------------------

    #[test]
    fn test_validate_extension_matches_sync_success() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("image.png");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            .expect("write");

        assert!(validate_extension_matches_sync(&path).is_ok());
    }

    #[test]
    fn test_validate_extension_matches_sync_spoofed() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("malware.jpg");

        // Write ELF but claim it's a JPEG
        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00])
            .expect("write");

        assert!(validate_extension_matches_sync(&path).is_err());
    }

    #[test]
    fn test_validate_extension_matches_sync_jpeg_alias() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("photo.jpeg");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0xFF, 0xD8, 0xFF, 0xE0]).expect("write");

        // jpeg extension should match JPEG magic
        assert!(validate_extension_matches_sync(&path).is_ok());
    }

    #[test]
    fn test_validate_extension_sync_unknown_type() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("random.xyz");

        let mut file = File::create(&path).expect("create file");
        file.write_all(b"random data").expect("write");

        // Unknown types should pass (can't validate)
        assert!(validate_extension_matches_sync(&path).is_ok());
    }

    // ----------------------------------------
    // validate_extension_matches Tests (Async)
    // ----------------------------------------

    #[tokio::test]
    async fn test_validate_extension_matches_async_success() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("image_async.png");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            .expect("write");

        assert!(validate_extension_matches(path).await.is_ok());
    }

    // ----------------------------------------
    // Adversarial Tests
    // ----------------------------------------

    #[test]
    fn test_adversarial_exe_disguised_as_png() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("innocent.png");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00])
            .expect("write");

        // Should fail all validations
        assert!(validate_image_sync(&path).is_err());
        assert!(validate_not_dangerous_sync(&path).is_err());
        assert!(validate_extension_matches_sync(&path).is_err());
    }

    #[test]
    fn test_adversarial_script_disguised_as_txt() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("readme.txt");

        let mut file = File::create(&path).expect("create file");
        file.write_all(b"#!/bin/bash\nrm -rf /\n").expect("write");

        assert!(validate_not_dangerous_sync(&path).is_err());
    }

    #[test]
    fn test_adversarial_pe_in_docx() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("document.docx");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00])
            .expect("write");

        // Extension validation should fail
        assert!(validate_extension_matches_sync(&path).is_err());
    }

    #[test]
    fn test_adversarial_wasm_disguised() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("data.bin");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00])
            .expect("write");

        assert!(validate_not_dangerous_sync(&path).is_err());
    }

    #[test]
    fn test_adversarial_empty_file() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("empty.png");

        File::create(&path).expect("create file");

        // Empty files should fail image validation
        assert!(validate_image_sync(&path).is_err());

        // But pass safety validation (nothing to execute)
        assert!(validate_not_dangerous_sync(&path).is_ok());
    }

    #[test]
    fn test_adversarial_type_mismatch() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("document.pdf");

        // Write PNG header but expect PDF
        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            .expect("write");

        assert!(validate_file_type_sync(&path, MagicFileType::Pdf).is_err());
        assert!(validate_file_type_sync(&path, MagicFileType::Png).is_ok());
    }
}
