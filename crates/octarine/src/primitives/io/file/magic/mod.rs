//! Magic byte detection for file type identification
//!
//! Pure detection functions that identify file types by examining file content
//! (magic bytes/signatures) rather than relying on file extensions.
//!
//! # Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No I/O operations (takes `&[u8]` input)
//! - Returns data only
//!
//! # Why Magic Bytes?
//!
//! File extensions can be spoofed. A malicious file named `safe.jpg` could actually
//! be an executable. Magic byte detection examines the actual file content to
//! determine its true type, preventing file upload attacks and other security issues.
//!
//! # Module Structure
//!
//! - [`types`] - Core types (`MagicFileType`, `MagicResult`)
//! - [`detectors`] - Category-specific detection functions
//! - [`convenience`] - Simple boolean check functions
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::io::file::magic::{detect_magic, MagicResult};
//!
//! let header = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]; // PNG
//! let result = detect_magic(header);
//! assert_eq!(result.file_type, Some(MagicFileType::Png));
//! ```
//!
//! # Supported Formats
//!
//! ## Images
//! - PNG, JPEG, GIF, BMP, WebP, TIFF, ICO, HEIC, AVIF
//!
//! ## Documents
//! - PDF, RTF
//!
//! ## Archives
//! - ZIP, GZIP, BZIP2, XZ, 7Z, RAR, TAR, ZSTD
//!
//! ## Executables
//! - ELF (Linux), Mach-O (macOS), PE/MZ (Windows), WASM
//!
//! ## Media
//! - MP3, MP4, WebM, MKV, OGG, FLAC, WAV, AVI, AIFF, M4A, MOV
//!
//! ## Data
//! - SQLite, XML
//!
//! ## Scripts
//! - Shell, Python, Node, Ruby, Perl (detected by shebang)

// Public API for file type validation - will be used by io/ layer
#![allow(dead_code)]

pub(crate) mod convenience;
pub(crate) mod detectors;
pub(crate) mod types;

// Re-export types
pub use types::{MagicFileType, MagicResult};

// Re-export convenience functions
pub use convenience::{is_archive_magic, is_dangerous_magic, is_executable_magic, is_image_magic};

// ============================================================================
// Constants
// ============================================================================

/// Minimum bytes needed for reliable detection
pub const MIN_MAGIC_BYTES: usize = 16;

/// Recommended bytes for best detection coverage
pub const RECOMMENDED_MAGIC_BYTES: usize = 64;

/// Maximum bytes we'll ever need to examine
pub const MAX_MAGIC_BYTES: usize = 262;

// ============================================================================
// Core Detection Function
// ============================================================================

/// Detect file type from magic bytes
///
/// Examines the provided byte slice and attempts to identify the file type
/// based on magic byte signatures.
///
/// # Arguments
///
/// * `data` - Byte slice containing file header (ideally 64+ bytes)
///
/// # Returns
///
/// `MagicResult` containing the detected type and confidence level
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::io::file::magic::detect_magic;
///
/// // PNG file signature
/// let png_header = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
/// let result = detect_magic(png_header);
/// assert!(result.is_detected());
/// ```
#[must_use]
pub fn detect_magic(data: &[u8]) -> MagicResult {
    use detectors::{
        detect_archive, detect_data, detect_document, detect_executable, detect_image,
        detect_media, detect_script,
    };

    let len = data.len();

    if len < 2 {
        return MagicResult::unknown(len);
    }

    // Check signatures in order of specificity/commonality

    // Images (very common, check first)
    if let Some(result) = detect_image(data) {
        return result;
    }

    // Archives (common attack vector)
    if let Some(result) = detect_archive(data) {
        return result;
    }

    // Executables (security critical)
    if let Some(result) = detect_executable(data) {
        return result;
    }

    // Documents
    if let Some(result) = detect_document(data) {
        return result;
    }

    // Media (audio/video)
    if let Some(result) = detect_media(data) {
        return result;
    }

    // Data formats
    if let Some(result) = detect_data(data) {
        return result;
    }

    // Scripts (shebang)
    if let Some(result) = detect_script(data) {
        return result;
    }

    MagicResult::unknown(len)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ----------------------------------------
    // Core detect_magic Tests
    // ----------------------------------------

    #[test]
    fn test_detect_magic_png() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];
        let result = detect_magic(&png);
        assert_eq!(result.file_type, Some(MagicFileType::Png));
        assert_eq!(result.confidence, 100);
    }

    #[test]
    fn test_detect_magic_jpeg() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0];
        let result = detect_magic(&jpeg);
        assert_eq!(result.file_type, Some(MagicFileType::Jpeg));
    }

    #[test]
    fn test_detect_magic_gif() {
        let gif = b"GIF89a\x00\x00";
        let result = detect_magic(gif);
        assert_eq!(result.file_type, Some(MagicFileType::Gif));
    }

    #[test]
    fn test_detect_magic_zip() {
        let zip = [0x50, 0x4B, 0x03, 0x04];
        let result = detect_magic(&zip);
        assert_eq!(result.file_type, Some(MagicFileType::ZipArchive));
    }

    #[test]
    fn test_detect_magic_gzip() {
        let gzip = [0x1F, 0x8B, 0x08];
        let result = detect_magic(&gzip);
        assert_eq!(result.file_type, Some(MagicFileType::Gzip));
    }

    #[test]
    fn test_detect_magic_elf() {
        let elf = [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01];
        let result = detect_magic(&elf);
        assert_eq!(result.file_type, Some(MagicFileType::Elf));
    }

    #[test]
    fn test_detect_magic_pe() {
        let pe = [0x4D, 0x5A, 0x90, 0x00];
        let result = detect_magic(&pe);
        assert_eq!(result.file_type, Some(MagicFileType::Pe));
    }

    #[test]
    fn test_detect_magic_pdf() {
        let pdf = b"%PDF-1.4";
        let result = detect_magic(pdf);
        assert_eq!(result.file_type, Some(MagicFileType::Pdf));
    }

    #[test]
    fn test_detect_magic_mp3() {
        let mp3 = b"ID3\x04\x00";
        let result = detect_magic(mp3);
        assert_eq!(result.file_type, Some(MagicFileType::Mp3));
    }

    #[test]
    fn test_detect_magic_sqlite() {
        let sqlite = b"SQLite format 3\0";
        let result = detect_magic(sqlite);
        assert_eq!(result.file_type, Some(MagicFileType::Sqlite));
    }

    #[test]
    fn test_detect_magic_shell_script() {
        let sh = b"#!/bin/bash\necho hello";
        let result = detect_magic(sh);
        assert_eq!(result.file_type, Some(MagicFileType::ShellScript));
    }

    #[test]
    fn test_detect_magic_python_script() {
        let py = b"#!/usr/bin/env python3\nprint()";
        let result = detect_magic(py);
        assert_eq!(result.file_type, Some(MagicFileType::PythonScript));
    }

    // ----------------------------------------
    // Edge Cases
    // ----------------------------------------

    #[test]
    fn test_detect_magic_empty() {
        let result = detect_magic(&[]);
        assert!(!result.is_detected());
        assert_eq!(result.bytes_examined, 0);
    }

    #[test]
    fn test_detect_magic_single_byte() {
        let result = detect_magic(&[0x00]);
        assert!(!result.is_detected());
        assert_eq!(result.bytes_examined, 1);
    }

    #[test]
    fn test_detect_magic_unknown() {
        let unknown = b"This is random text";
        let result = detect_magic(unknown);
        assert!(!result.is_detected());
    }

    // ----------------------------------------
    // Adversarial Tests
    // ----------------------------------------

    #[test]
    fn test_adversarial_truncated_png() {
        // Only first 4 bytes - not enough for full PNG signature
        let truncated = [0x89, 0x50, 0x4E, 0x47];
        let result = detect_magic(&truncated);
        assert!(result.file_type != Some(MagicFileType::Png));
    }

    #[test]
    fn test_adversarial_near_miss_png() {
        // Off-by-one in PNG signature (0x88 instead of 0x89)
        let near_miss = [0x88, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let result = detect_magic(&near_miss);
        assert!(result.file_type != Some(MagicFileType::Png));
    }

    #[test]
    fn test_adversarial_null_prefix() {
        // Null bytes before PNG header
        let null_prefix = [0x00, 0x00, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let result = detect_magic(&null_prefix);
        // Should NOT detect as PNG - header must be at offset 0
        assert!(result.file_type != Some(MagicFileType::Png));
    }

    #[test]
    fn test_adversarial_exe_with_image_extension_content() {
        // ELF binary
        let elf = [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
        assert!(is_dangerous_magic(&elf));
        assert!(is_executable_magic(&elf));
        assert!(!is_image_magic(&elf));
    }

    #[test]
    fn test_adversarial_polyglot_zip() {
        // ZIP starting file
        let zip = [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00];
        let result = detect_magic(&zip);
        assert_eq!(result.file_type, Some(MagicFileType::ZipArchive));
        assert!(is_dangerous_magic(&zip));
    }

    #[test]
    fn test_adversarial_shebang_variants() {
        assert!(is_dangerous_magic(b"#!/bin/sh\n"));
        assert!(is_dangerous_magic(b"#!/bin/bash\n"));
        assert!(is_dangerous_magic(b"#!/usr/bin/env python\n"));
        assert!(is_dangerous_magic(b"#!/usr/bin/env node\n"));
        assert!(is_dangerous_magic(b"#! /bin/sh\n"));
    }

    #[test]
    fn test_adversarial_gzip_bomb_signature() {
        // GZIP signature - detected even if it's a gzip bomb
        let gzip = [0x1F, 0x8B, 0x08, 0x00];
        let result = detect_magic(&gzip);
        assert_eq!(result.file_type, Some(MagicFileType::Gzip));
        assert!(is_dangerous_magic(&gzip));
    }

    #[test]
    fn test_adversarial_all_zeros() {
        let zeros = [0x00u8; 64];
        let result = detect_magic(&zeros);
        assert!(result.file_type != Some(MagicFileType::Elf));
        assert!(result.file_type != Some(MagicFileType::Pe));
        assert!(!is_executable_magic(&zeros));
    }

    #[test]
    fn test_adversarial_all_0xff() {
        // All 0xFF - could be mistaken for JPEG start
        let all_ff = [0xFFu8; 64];
        let result = detect_magic(&all_ff);
        // JPEG requires FF D8 FF, not FF FF FF
        assert!(result.file_type != Some(MagicFileType::Jpeg));
    }

    #[test]
    fn test_adversarial_wasm_detection() {
        let wasm = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        assert!(is_executable_magic(&wasm));
        assert!(is_dangerous_magic(&wasm));
    }

    #[test]
    fn test_adversarial_macho_detection() {
        // Mach-O 64-bit
        let macho64 = [0xCF, 0xFA, 0xED, 0xFE, 0x07, 0x00, 0x00, 0x01];
        assert!(is_executable_magic(&macho64));
        assert!(is_dangerous_magic(&macho64));

        // Fat/Universal binary
        let fat = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02];
        assert!(is_executable_magic(&fat));
    }

    #[test]
    fn test_adversarial_image_not_dangerous() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0];
        let gif = b"GIF89a";
        let bmp = [0x42, 0x4D];

        assert!(!is_dangerous_magic(&png));
        assert!(!is_dangerous_magic(&jpeg));
        assert!(!is_dangerous_magic(gif));
        assert!(!is_dangerous_magic(&bmp));
    }

    #[test]
    fn test_adversarial_pdf_not_dangerous() {
        let pdf = b"%PDF-1.4";
        assert!(!is_dangerous_magic(pdf));
        assert!(!is_executable_magic(pdf));
    }

    #[test]
    fn test_adversarial_tar_boundary() {
        // TAR detection requires checking at offset 257
        let mut tar_file = vec![0u8; 262];
        if let Some(slice) = tar_file.get_mut(257..262) {
            slice.copy_from_slice(b"ustar");
        }
        let result = detect_magic(&tar_file);
        assert_eq!(result.file_type, Some(MagicFileType::Tar));
    }

    #[test]
    fn test_adversarial_tar_too_short() {
        // TAR detection offset (257) - file too short
        let short_tar = vec![0u8; 256];
        let result = detect_magic(&short_tar);
        assert!(result.file_type != Some(MagicFileType::Tar));
    }
}
