//! Convenience functions for magic byte detection
//!
//! Simple boolean-returning functions for common file type checks.

use super::detectors::{detect_archive, detect_executable, detect_image, detect_script};

/// Check if magic bytes indicate an image file
#[must_use]
pub fn is_image_magic(data: &[u8]) -> bool {
    detect_image(data).is_some()
}

/// Check if magic bytes indicate an archive file
#[must_use]
pub fn is_archive_magic(data: &[u8]) -> bool {
    detect_archive(data).is_some()
}

/// Check if magic bytes indicate an executable file
#[must_use]
pub fn is_executable_magic(data: &[u8]) -> bool {
    detect_executable(data).is_some()
}

/// Check if magic bytes indicate a potentially dangerous file type
///
/// Returns true for executables, archives (can contain executables),
/// and scripts.
#[must_use]
pub fn is_dangerous_magic(data: &[u8]) -> bool {
    if let Some(result) = detect_executable(data) {
        return result.is_detected();
    }
    if let Some(result) = detect_archive(data) {
        return result.is_detected();
    }
    if let Some(result) = detect_script(data) {
        return result.is_detected();
    }
    false
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ----------------------------------------
    // is_image_magic Tests
    // ----------------------------------------

    #[test]
    fn test_is_image_magic_png() {
        assert!(is_image_magic(&[
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
        ]));
    }

    #[test]
    fn test_is_image_magic_jpeg() {
        assert!(is_image_magic(&[0xFF, 0xD8, 0xFF, 0xE0]));
    }

    #[test]
    fn test_is_image_magic_gif() {
        assert!(is_image_magic(b"GIF89a"));
    }

    #[test]
    fn test_is_image_magic_false_for_pdf() {
        assert!(!is_image_magic(b"%PDF-1.4"));
    }

    #[test]
    fn test_is_image_magic_false_for_executable() {
        assert!(!is_image_magic(&[0x7F, 0x45, 0x4C, 0x46]));
    }

    // ----------------------------------------
    // is_archive_magic Tests
    // ----------------------------------------

    #[test]
    fn test_is_archive_magic_zip() {
        assert!(is_archive_magic(&[0x50, 0x4B, 0x03, 0x04]));
    }

    #[test]
    fn test_is_archive_magic_gzip() {
        assert!(is_archive_magic(&[0x1F, 0x8B]));
    }

    #[test]
    fn test_is_archive_magic_7z() {
        assert!(is_archive_magic(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]));
    }

    #[test]
    fn test_is_archive_magic_rar() {
        assert!(is_archive_magic(b"Rar!\x1A\x07"));
    }

    #[test]
    fn test_is_archive_magic_false_for_image() {
        assert!(!is_archive_magic(&[
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
        ]));
    }

    // ----------------------------------------
    // is_executable_magic Tests
    // ----------------------------------------

    #[test]
    fn test_is_executable_magic_elf() {
        assert!(is_executable_magic(&[0x7F, 0x45, 0x4C, 0x46]));
    }

    #[test]
    fn test_is_executable_magic_pe() {
        assert!(is_executable_magic(&[0x4D, 0x5A]));
    }

    #[test]
    fn test_is_executable_magic_wasm() {
        assert!(is_executable_magic(&[0x00, 0x61, 0x73, 0x6D]));
    }

    #[test]
    fn test_is_executable_magic_macho() {
        assert!(is_executable_magic(&[0xCF, 0xFA, 0xED, 0xFE]));
    }

    #[test]
    fn test_is_executable_magic_false_for_image() {
        assert!(!is_executable_magic(&[
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
        ]));
    }

    // ----------------------------------------
    // is_dangerous_magic Tests
    // ----------------------------------------

    #[test]
    fn test_is_dangerous_magic_elf() {
        assert!(is_dangerous_magic(&[0x7F, 0x45, 0x4C, 0x46]));
    }

    #[test]
    fn test_is_dangerous_magic_pe() {
        assert!(is_dangerous_magic(&[0x4D, 0x5A]));
    }

    #[test]
    fn test_is_dangerous_magic_wasm() {
        assert!(is_dangerous_magic(&[0x00, 0x61, 0x73, 0x6D]));
    }

    #[test]
    fn test_is_dangerous_magic_zip() {
        assert!(is_dangerous_magic(&[0x50, 0x4B, 0x03, 0x04]));
    }

    #[test]
    fn test_is_dangerous_magic_gzip() {
        assert!(is_dangerous_magic(&[0x1F, 0x8B]));
    }

    #[test]
    fn test_is_dangerous_magic_shell_script() {
        assert!(is_dangerous_magic(b"#!/bin/sh\n"));
    }

    #[test]
    fn test_is_dangerous_magic_python_script() {
        assert!(is_dangerous_magic(b"#!/usr/bin/env python\n"));
    }

    #[test]
    fn test_is_dangerous_magic_false_for_png() {
        assert!(!is_dangerous_magic(&[
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
        ]));
    }

    #[test]
    fn test_is_dangerous_magic_false_for_jpeg() {
        assert!(!is_dangerous_magic(&[0xFF, 0xD8, 0xFF, 0xE0]));
    }

    #[test]
    fn test_is_dangerous_magic_false_for_gif() {
        assert!(!is_dangerous_magic(b"GIF89a"));
    }

    #[test]
    fn test_is_dangerous_magic_false_for_pdf() {
        // PDFs can contain JS but we don't classify as dangerous
        assert!(!is_dangerous_magic(b"%PDF-1.4"));
    }

    // ----------------------------------------
    // Adversarial Tests
    // ----------------------------------------

    #[test]
    fn test_adversarial_exe_disguised_as_image() {
        // ELF binary - dangerous regardless of extension
        let elf = [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
        assert!(is_dangerous_magic(&elf));
        assert!(is_executable_magic(&elf));
        assert!(!is_image_magic(&elf));
    }

    #[test]
    fn test_adversarial_polyglot_zip() {
        // ZIP starting file should be dangerous
        let zip = [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00];
        assert!(is_dangerous_magic(&zip));
        assert!(is_archive_magic(&zip));
    }

    #[test]
    fn test_adversarial_shebang_variants() {
        assert!(is_dangerous_magic(b"#!/bin/sh\n"));
        assert!(is_dangerous_magic(b"#!/bin/bash\n"));
        assert!(is_dangerous_magic(b"#!/usr/bin/env python\n"));
        assert!(is_dangerous_magic(b"#!/usr/bin/env node\n"));
        assert!(is_dangerous_magic(b"#! /bin/sh\n")); // Space after #!
    }

    #[test]
    fn test_adversarial_all_zeros_safe() {
        let zeros = [0x00u8; 64];
        assert!(!is_dangerous_magic(&zeros));
        assert!(!is_executable_magic(&zeros));
    }

    #[test]
    fn test_adversarial_image_formats_safe() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0];
        let gif = b"GIF89a";
        let bmp = [0x42, 0x4D];

        assert!(!is_dangerous_magic(&png));
        assert!(!is_dangerous_magic(&jpeg));
        assert!(!is_dangerous_magic(gif));
        assert!(!is_dangerous_magic(&bmp));
    }
}
