//! Magic byte detection with observability
//!
//! Wrappers around primitives with automatic audit trails via observe.
//! Follows async-first design: async functions by default, `_sync` suffix for blocking.

use std::path::Path;

use crate::observe::{self, Problem};
use crate::primitives::io::file as prim;
use crate::primitives::runtime::r#async::spawn_blocking;

pub use prim::{MAX_MAGIC_BYTES, MagicFileType, MagicResult};

// ============================================================================
// In-Memory Detection
// ============================================================================

/// Detect file type from magic bytes with audit trail
///
/// Examines the provided byte slice and identifies the file type.
/// All detections are logged via observe for compliance.
///
/// # Arguments
///
/// * `data` - Byte slice containing file header (ideally 64+ bytes)
///
/// # Returns
///
/// `MagicResult` with detected type, confidence, and bytes examined
#[must_use]
pub fn detect_magic(data: &[u8]) -> MagicResult {
    let result = prim::detect_magic(data);

    if result.is_detected() {
        if let Some(ft) = result.file_type {
            observe::trace(
                "io.magic.detect",
                format!(
                    "Detected {} (confidence: {}%, {} bytes)",
                    ft.mime_type(),
                    result.confidence,
                    result.bytes_examined
                ),
            );
        }
    } else {
        observe::trace(
            "io.magic.detect",
            format!(
                "Unknown file type ({} bytes examined)",
                result.bytes_examined
            ),
        );
    }

    result
}

/// Check if magic bytes indicate an image file
#[must_use]
pub fn is_image_magic(data: &[u8]) -> bool {
    prim::is_image_magic(data)
}

/// Check if magic bytes indicate an archive file
#[must_use]
pub fn is_archive_magic(data: &[u8]) -> bool {
    prim::is_archive_magic(data)
}

/// Check if magic bytes indicate an executable file
#[must_use]
pub fn is_executable_magic(data: &[u8]) -> bool {
    prim::is_executable_magic(data)
}

/// Check if magic bytes indicate a potentially dangerous file type
///
/// Returns true for executables, archives (can contain executables), and scripts.
#[must_use]
pub fn is_dangerous_magic(data: &[u8]) -> bool {
    prim::is_dangerous_magic(data)
}

// ============================================================================
// File-Based Detection (Async - Default)
// ============================================================================

/// Detect file type by reading the file's magic bytes (async)
///
/// Reads up to 262 bytes from the file and detects its type.
/// All operations are logged via observe.
///
/// # Errors
///
/// Returns `Problem::Io` if the file cannot be read.
pub async fn detect_file_type(
    path: impl AsRef<Path> + Send + 'static,
) -> Result<MagicResult, Problem> {
    let path = path.as_ref().to_path_buf();
    let path_str = path.display().to_string();

    observe::trace("io.magic.detect_file", format!("Examining {}", path_str));

    // Read header bytes asynchronously
    let header = read_magic_bytes(path.clone()).await?;
    let result = prim::detect_magic(&header);

    if result.is_detected() {
        if let Some(ft) = result.file_type {
            observe::debug(
                "io.magic.detect_file",
                format!(
                    "File {} detected as {} (confidence: {}%)",
                    path_str,
                    ft.mime_type(),
                    result.confidence
                ),
            );
        }
    } else {
        observe::debug(
            "io.magic.detect_file",
            format!("File {} has unknown type", path_str),
        );
    }

    Ok(result)
}

/// Check if a file is an image based on magic bytes (async)
///
/// # Errors
///
/// Returns `Problem::Io` if the file cannot be read.
pub async fn is_image_file(path: impl AsRef<Path> + Send + 'static) -> Result<bool, Problem> {
    let header = read_magic_bytes(path).await?;
    Ok(prim::is_image_magic(&header))
}

/// Check if a file is an archive based on magic bytes (async)
///
/// # Errors
///
/// Returns `Problem::Io` if the file cannot be read.
pub async fn is_archive_file(path: impl AsRef<Path> + Send + 'static) -> Result<bool, Problem> {
    let header = read_magic_bytes(path).await?;
    Ok(prim::is_archive_magic(&header))
}

/// Check if a file is an executable based on magic bytes (async)
///
/// # Errors
///
/// Returns `Problem::Io` if the file cannot be read.
pub async fn is_executable_file(path: impl AsRef<Path> + Send + 'static) -> Result<bool, Problem> {
    let header = read_magic_bytes(path).await?;
    Ok(prim::is_executable_magic(&header))
}

/// Check if a file is potentially dangerous based on magic bytes (async)
///
/// Dangerous types include executables, archives, and scripts.
///
/// # Errors
///
/// Returns `Problem::Io` if the file cannot be read.
pub async fn is_dangerous_file(path: impl AsRef<Path> + Send + 'static) -> Result<bool, Problem> {
    let header = read_magic_bytes(path).await?;
    Ok(prim::is_dangerous_magic(&header))
}

// ============================================================================
// File-Based Detection (Sync - Explicit Opt-In)
// ============================================================================

/// Detect file type by reading the file's magic bytes (sync, blocking)
///
/// **Warning**: This WILL block the current thread.
pub fn detect_file_type_sync(path: impl AsRef<Path>) -> Result<MagicResult, Problem> {
    let path = path.as_ref();
    let path_str = path.display().to_string();

    observe::trace("io.magic.detect_file", format!("Examining {}", path_str));

    // Read header bytes
    let header = read_magic_bytes_sync(path)?;
    let result = prim::detect_magic(&header);

    if result.is_detected() {
        if let Some(ft) = result.file_type {
            observe::debug(
                "io.magic.detect_file",
                format!(
                    "File {} detected as {} (confidence: {}%)",
                    path_str,
                    ft.mime_type(),
                    result.confidence
                ),
            );
        }
    } else {
        observe::debug(
            "io.magic.detect_file",
            format!("File {} has unknown type", path_str),
        );
    }

    Ok(result)
}

/// Check if a file is an image based on magic bytes (sync, blocking)
pub fn is_image_file_sync(path: impl AsRef<Path>) -> Result<bool, Problem> {
    let header = read_magic_bytes_sync(path)?;
    Ok(prim::is_image_magic(&header))
}

/// Check if a file is an archive based on magic bytes (sync, blocking)
pub fn is_archive_file_sync(path: impl AsRef<Path>) -> Result<bool, Problem> {
    let header = read_magic_bytes_sync(path)?;
    Ok(prim::is_archive_magic(&header))
}

/// Check if a file is an executable based on magic bytes (sync, blocking)
pub fn is_executable_file_sync(path: impl AsRef<Path>) -> Result<bool, Problem> {
    let header = read_magic_bytes_sync(path)?;
    Ok(prim::is_executable_magic(&header))
}

/// Check if a file is potentially dangerous based on magic bytes (sync, blocking)
pub fn is_dangerous_file_sync(path: impl AsRef<Path>) -> Result<bool, Problem> {
    let header = read_magic_bytes_sync(path)?;
    Ok(prim::is_dangerous_magic(&header))
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Read magic bytes from a file (async)
pub(crate) async fn read_magic_bytes(
    path: impl AsRef<Path> + Send + 'static,
) -> Result<Vec<u8>, Problem> {
    let path = path.as_ref().to_path_buf();
    let path_for_error = path.clone();

    spawn_blocking(move || {
        use std::fs::File;
        use std::io::Read;

        let mut file = File::open(&path)
            .map_err(|e| Problem::io(format!("Failed to open file {}: {}", path.display(), e)))?;

        let mut buffer = vec![0u8; MAX_MAGIC_BYTES];
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|e| Problem::io(format!("Failed to read file {}: {}", path.display(), e)))?;

        buffer.truncate(bytes_read);
        Ok(buffer)
    })
    .await
    .map_err(|e| Problem::operation_failed(format!("Async read_magic_bytes failed: {}", e)))?
    .map_err(|e: Problem| {
        Problem::io(format!(
            "Failed to read magic bytes from {:?}: {}",
            path_for_error, e
        ))
    })
}

/// Read magic bytes from a file (sync)
pub(crate) fn read_magic_bytes_sync(path: impl AsRef<Path>) -> Result<Vec<u8>, Problem> {
    use std::fs::File;
    use std::io::Read;

    let path = path.as_ref();
    let mut file = File::open(path)
        .map_err(|e| Problem::io(format!("Failed to open file {}: {}", path.display(), e)))?;

    let mut buffer = vec![0u8; MAX_MAGIC_BYTES];
    let bytes_read = file
        .read(&mut buffer)
        .map_err(|e| Problem::io(format!("Failed to read file {}: {}", path.display(), e)))?;

    buffer.truncate(bytes_read);
    Ok(buffer)
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
    // In-Memory Detection Tests
    // ----------------------------------------

    #[test]
    fn test_detect_magic_png() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let result = detect_magic(&png);
        assert_eq!(result.file_type, Some(MagicFileType::Png));
    }

    #[test]
    fn test_detect_magic_jpeg() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0];
        let result = detect_magic(&jpeg);
        assert_eq!(result.file_type, Some(MagicFileType::Jpeg));
    }

    #[test]
    fn test_detect_magic_elf() {
        let elf = [0x7F, 0x45, 0x4C, 0x46, 0x02];
        let result = detect_magic(&elf);
        assert_eq!(result.file_type, Some(MagicFileType::Elf));
    }

    #[test]
    fn test_is_image_magic_true() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert!(is_image_magic(&png));
    }

    #[test]
    fn test_is_image_magic_false() {
        let elf = [0x7F, 0x45, 0x4C, 0x46];
        assert!(!is_image_magic(&elf));
    }

    #[test]
    fn test_is_dangerous_magic_exe() {
        let elf = [0x7F, 0x45, 0x4C, 0x46];
        assert!(is_dangerous_magic(&elf));
    }

    #[test]
    fn test_is_dangerous_magic_archive() {
        let zip = [0x50, 0x4B, 0x03, 0x04];
        assert!(is_dangerous_magic(&zip));
    }

    #[test]
    fn test_is_dangerous_magic_script() {
        assert!(is_dangerous_magic(b"#!/bin/bash\n"));
    }

    #[test]
    fn test_is_dangerous_magic_image_safe() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert!(!is_dangerous_magic(&png));
    }

    // ----------------------------------------
    // File-Based Detection Tests (Sync)
    // ----------------------------------------

    #[test]
    fn test_detect_file_type_sync_png() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.png");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00])
            .expect("write");

        let result = detect_file_type_sync(&path).expect("detect");
        assert_eq!(result.file_type, Some(MagicFileType::Png));
    }

    #[test]
    fn test_is_image_file_sync_true() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("image.png");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            .expect("write");

        assert!(is_image_file_sync(&path).expect("check"));
    }

    #[test]
    fn test_is_image_file_sync_false() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("text.txt");

        let mut file = File::create(&path).expect("create file");
        file.write_all(b"Hello, world!").expect("write");

        assert!(!is_image_file_sync(&path).expect("check"));
    }

    #[test]
    fn test_is_dangerous_file_sync_exe() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("program");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00])
            .expect("write");

        assert!(is_dangerous_file_sync(&path).expect("check"));
    }

    #[test]
    fn test_is_dangerous_file_sync_image_safe() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("image.png");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            .expect("write");

        assert!(!is_dangerous_file_sync(&path).expect("check"));
    }

    #[test]
    fn test_is_archive_file_sync() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("archive.zip");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x50, 0x4B, 0x03, 0x04, 0x00, 0x00])
            .expect("write");

        assert!(is_archive_file_sync(&path).expect("check"));
    }

    #[test]
    fn test_is_executable_file_sync() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("binary");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x7F, 0x45, 0x4C, 0x46, 0x02])
            .expect("write");

        assert!(is_executable_file_sync(&path).expect("check"));
    }

    // ----------------------------------------
    // File-Based Detection Tests (Async)
    // ----------------------------------------

    #[tokio::test]
    async fn test_detect_file_type_async_png() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test_async.png");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00])
            .expect("write");

        let result = detect_file_type(path).await.expect("detect");
        assert_eq!(result.file_type, Some(MagicFileType::Png));
    }

    #[tokio::test]
    async fn test_is_image_file_async() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("image_async.png");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            .expect("write");

        assert!(is_image_file(path).await.expect("check"));
    }

    #[tokio::test]
    async fn test_is_dangerous_file_async() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("program_async");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00])
            .expect("write");

        assert!(is_dangerous_file(path).await.expect("check"));
    }

    // ----------------------------------------
    // Error Handling Tests
    // ----------------------------------------

    #[test]
    fn test_detect_file_type_sync_not_found() {
        let result = detect_file_type_sync("/nonexistent/file.txt");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_detect_file_type_async_not_found() {
        let result = detect_file_type("/nonexistent/file.txt").await;
        assert!(result.is_err());
    }

    // ----------------------------------------
    // Adversarial Tests
    // ----------------------------------------

    #[test]
    fn test_adversarial_empty_file() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("empty.bin");

        File::create(&path).expect("create file");

        let result = detect_file_type_sync(&path).expect("detect");
        assert!(!result.is_detected());
        assert!(!is_dangerous_file_sync(&path).expect("check"));
    }

    #[test]
    fn test_adversarial_partial_png_header() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("partial.png");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x89, 0x50]).expect("write");

        let result = detect_file_type_sync(&path).expect("detect");
        assert!(result.file_type != Some(MagicFileType::Png));
    }

    #[test]
    fn test_adversarial_script_in_file() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("script.sh");

        let mut file = File::create(&path).expect("create file");
        file.write_all(b"#!/bin/bash\necho 'hello'").expect("write");

        assert!(is_dangerous_file_sync(&path).expect("check"));
    }

    #[test]
    fn test_adversarial_wasm_in_file() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("module.wasm");

        let mut file = File::create(&path).expect("create file");
        file.write_all(&[0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00])
            .expect("write");

        assert!(is_executable_file_sync(&path).expect("check"));
        assert!(is_dangerous_file_sync(&path).expect("check"));
    }
}
