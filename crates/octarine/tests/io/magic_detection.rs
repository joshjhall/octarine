#![allow(clippy::panic, clippy::expect_used)]

use octarine::io::{
    MagicFileType, detect_file_type_sync, detect_magic, is_dangerous_file_sync, is_image_file_sync,
    validate_extension_matches_sync, validate_file_type_sync, validate_image_sync,
    validate_not_dangerous_sync,
};
use tempfile::tempdir;

// =========================================================================
// In-memory → file-based consistency
// =========================================================================

/// In-memory detect_magic and file-based detect_file_type_sync agree on type.
#[test]
fn test_inmemory_and_file_detection_agree() {
    let dir = tempdir().expect("create temp dir");

    let test_cases: Vec<(&str, &[u8], MagicFileType)> = vec![
        (
            "test.png",
            &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
            MagicFileType::Png,
        ),
        ("test.jpg", &[0xFF, 0xD8, 0xFF, 0xE0], MagicFileType::Jpeg),
        ("test.pdf", b"%PDF-1.4\n", MagicFileType::Pdf),
        (
            "test.zip",
            &[0x50, 0x4B, 0x03, 0x04, 0x00, 0x00],
            MagicFileType::ZipArchive,
        ),
        (
            "test.elf",
            &[0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01],
            MagicFileType::Elf,
        ),
    ];

    for (filename, bytes, expected_type) in test_cases {
        // In-memory
        let mem_result = detect_magic(bytes);
        assert_eq!(
            mem_result.file_type,
            Some(expected_type),
            "In-memory detection failed for {filename}"
        );

        // File-based
        let path = dir.path().join(filename);
        std::fs::write(&path, bytes).expect("write test file");
        let file_result = detect_file_type_sync(&path).expect("file detection");
        assert_eq!(
            file_result.file_type,
            Some(expected_type),
            "File-based detection failed for {filename}"
        );

        // They should agree
        assert_eq!(mem_result.file_type, file_result.file_type);
    }
}

// =========================================================================
// Extension spoofing matrix
// =========================================================================

/// ELF binary disguised as .jpg → validate_extension_matches rejects it.
#[test]
fn test_spoofing_elf_as_jpg() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("photo.jpg");

    std::fs::write(&path, [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00]).expect("write ELF");

    assert!(validate_extension_matches_sync(&path).is_err());
    assert!(validate_image_sync(&path).is_err());
    assert!(validate_not_dangerous_sync(&path).is_err());
    assert!(is_dangerous_file_sync(&path).expect("check"));
}

/// Shell script disguised as .txt → validate_not_dangerous catches it.
#[test]
fn test_spoofing_script_as_txt() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("readme.txt");

    std::fs::write(&path, b"#!/bin/bash\nrm -rf /\n").expect("write script");

    assert!(validate_not_dangerous_sync(&path).is_err());
    assert!(is_dangerous_file_sync(&path).expect("check"));
}

/// PE executable disguised as .docx → validate_extension_matches catches it.
#[test]
fn test_spoofing_pe_as_docx() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("report.docx");

    std::fs::write(&path, [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]).expect("write PE");

    assert!(validate_extension_matches_sync(&path).is_err());
    assert!(is_dangerous_file_sync(&path).expect("check"));
}

/// PNG with correct .png extension → all validations pass.
#[test]
fn test_legitimate_png_passes_all() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("legitimate.png");

    std::fs::write(&path, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).expect("write PNG");

    validate_extension_matches_sync(&path).expect("extension should match");
    validate_image_sync(&path).expect("should be valid image");
    validate_not_dangerous_sync(&path).expect("PNG should not be dangerous");
    assert!(is_image_file_sync(&path).expect("check"));
    assert!(!is_dangerous_file_sync(&path).expect("check"));
}

/// JPEG alias: .jpeg extension matches JPEG magic bytes.
#[test]
fn test_jpeg_alias_extension() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("photo.jpeg");

    std::fs::write(&path, [0xFF, 0xD8, 0xFF, 0xE0]).expect("write JPEG");
    validate_extension_matches_sync(&path).expect("jpeg alias should match");
}

/// validate_file_type correctly matches and rejects.
#[test]
fn test_validate_file_type_match_and_mismatch() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("doc.pdf");

    std::fs::write(&path, b"%PDF-1.4\n").expect("write PDF");

    validate_file_type_sync(&path, MagicFileType::Pdf).expect("PDF should match PDF");
    assert!(
        validate_file_type_sync(&path, MagicFileType::Png).is_err(),
        "PDF should not match PNG"
    );
}

/// Empty file: not an image, not dangerous, detection returns None.
#[test]
fn test_empty_file_detection() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("empty.bin");

    std::fs::write(&path, b"").expect("write empty");

    let result = detect_file_type_sync(&path).expect("detect");
    assert!(!result.is_detected(), "Empty file should not be detected");

    assert!(
        validate_image_sync(&path).is_err(),
        "Empty file is not an image"
    );
    validate_not_dangerous_sync(&path).expect("Empty file is not dangerous");
}
