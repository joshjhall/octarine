//! Category-specific magic byte detection functions
//!
//! Pure detection functions that identify file types by examining magic bytes.
//! Each function handles a specific category of file types.

use super::types::{MagicFileType, MagicResult};

// ============================================================================
// Image Detection
// ============================================================================

/// Detect image file types from magic bytes
pub(crate) fn detect_image(data: &[u8]) -> Option<MagicResult> {
    let len = data.len();

    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if data.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some(MagicResult::detected(MagicFileType::Png, 100, len));
    }

    // JPEG: FF D8 FF
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some(MagicResult::detected(MagicFileType::Jpeg, 100, len));
    }

    // GIF: GIF87a or GIF89a
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Some(MagicResult::detected(MagicFileType::Gif, 100, len));
    }

    // BMP: 42 4D (BM)
    if data.starts_with(&[0x42, 0x4D]) {
        return Some(MagicResult::detected(MagicFileType::Bmp, 95, len));
    }

    // WebP: RIFF....WEBP
    if data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WEBP") {
        return Some(MagicResult::detected(MagicFileType::WebP, 100, len));
    }

    // TIFF: 49 49 2A 00 (little-endian) or 4D 4D 00 2A (big-endian)
    if data.starts_with(&[0x49, 0x49, 0x2A, 0x00]) || data.starts_with(&[0x4D, 0x4D, 0x00, 0x2A]) {
        return Some(MagicResult::detected(MagicFileType::Tiff, 100, len));
    }

    // ICO: 00 00 01 00
    if data.starts_with(&[0x00, 0x00, 0x01, 0x00]) {
        return Some(MagicResult::detected(MagicFileType::Ico, 95, len));
    }

    // HEIC/HEIF and AVIF: ftyp at offset 4
    if data.get(4..8) == Some(b"ftyp") {
        match data.get(8..12) {
            Some(b"heic") | Some(b"heix") | Some(b"mif1") => {
                return Some(MagicResult::detected(MagicFileType::Heic, 100, len));
            }
            Some(b"avif") => {
                return Some(MagicResult::detected(MagicFileType::Avif, 100, len));
            }
            _ => {}
        }
    }

    None
}

// ============================================================================
// Archive Detection
// ============================================================================

/// Detect archive file types from magic bytes
pub(crate) fn detect_archive(data: &[u8]) -> Option<MagicResult> {
    let len = data.len();

    // ZIP: 50 4B 03 04 or 50 4B 05 06 (empty) or 50 4B 07 08 (spanned)
    if data.starts_with(&[0x50, 0x4B, 0x03, 0x04])
        || data.starts_with(&[0x50, 0x4B, 0x05, 0x06])
        || data.starts_with(&[0x50, 0x4B, 0x07, 0x08])
    {
        return Some(MagicResult::detected(MagicFileType::ZipArchive, 100, len));
    }

    // GZIP: 1F 8B
    if data.starts_with(&[0x1F, 0x8B]) {
        return Some(MagicResult::detected(MagicFileType::Gzip, 100, len));
    }

    // BZIP2: BZh
    if data.starts_with(b"BZh") {
        return Some(MagicResult::detected(MagicFileType::Bzip2, 100, len));
    }

    // XZ: FD 37 7A 58 5A 00
    if data.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
        return Some(MagicResult::detected(MagicFileType::Xz, 100, len));
    }

    // 7Z: 37 7A BC AF 27 1C
    if data.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return Some(MagicResult::detected(MagicFileType::SevenZip, 100, len));
    }

    // RAR: Rar! 1A 07
    if data.starts_with(b"Rar!") && data.get(4..6) == Some(&[0x1A, 0x07]) {
        return Some(MagicResult::detected(MagicFileType::Rar, 100, len));
    }

    // Zstandard: 28 B5 2F FD
    if data.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return Some(MagicResult::detected(MagicFileType::Zstd, 100, len));
    }

    // TAR: Check for ustar at offset 257
    if data.get(257..262) == Some(b"ustar") {
        return Some(MagicResult::detected(MagicFileType::Tar, 100, len));
    }

    None
}

// ============================================================================
// Executable Detection
// ============================================================================

/// Detect executable file types from magic bytes
pub(crate) fn detect_executable(data: &[u8]) -> Option<MagicResult> {
    let len = data.len();

    // ELF: 7F 45 4C 46
    if data.starts_with(&[0x7F, 0x45, 0x4C, 0x46]) {
        return Some(MagicResult::detected(MagicFileType::Elf, 100, len));
    }

    // Mach-O: Various magic numbers
    if let Some(bytes) = data.get(0..4).and_then(|s| <[u8; 4]>::try_from(s).ok()) {
        let magic = u32::from_be_bytes(bytes);
        // 32-bit: 0xFEEDFACE, 0xCEFAEDFE
        // 64-bit: 0xFEEDFACF, 0xCFFAEDFE
        if magic == 0xFEED_FACE
            || magic == 0xCEFA_EDFE
            || magic == 0xFEED_FACF
            || magic == 0xCFFA_EDFE
        {
            return Some(MagicResult::detected(MagicFileType::MachO, 100, len));
        }
        // Fat/Universal: 0xCAFEBABE, 0xBEBAFECA
        if magic == 0xCAFE_BABE || magic == 0xBEBA_FECA {
            return Some(MagicResult::detected(MagicFileType::MachOFat, 100, len));
        }
    }

    // PE/MZ (Windows): 4D 5A (MZ)
    if data.starts_with(&[0x4D, 0x5A]) {
        return Some(MagicResult::detected(MagicFileType::Pe, 95, len));
    }

    // WebAssembly: 00 61 73 6D (\0asm)
    if data.starts_with(&[0x00, 0x61, 0x73, 0x6D]) {
        return Some(MagicResult::detected(MagicFileType::Wasm, 100, len));
    }

    None
}

// ============================================================================
// Document Detection
// ============================================================================

/// Detect document file types from magic bytes
pub(crate) fn detect_document(data: &[u8]) -> Option<MagicResult> {
    let len = data.len();

    // PDF: %PDF
    if data.starts_with(b"%PDF") {
        return Some(MagicResult::detected(MagicFileType::Pdf, 100, len));
    }

    // RTF: {\rtf
    if data.starts_with(b"{\\rtf") {
        return Some(MagicResult::detected(MagicFileType::Rtf, 100, len));
    }

    None
}

// ============================================================================
// Media Detection (Audio/Video)
// ============================================================================

/// Detect media (audio/video) file types from magic bytes
pub(crate) fn detect_media(data: &[u8]) -> Option<MagicResult> {
    let len = data.len();

    // MP3: FF FB/FA/F3/F2 (sync word) or ID3 tag
    if data.starts_with(b"ID3") {
        return Some(MagicResult::detected(MagicFileType::Mp3, 100, len));
    }
    // MP3 sync word: 0xFF followed by byte with upper 3 bits set
    if matches!(data.get(0..2), Some(&[0xFF, second]) if (second & 0xE0) == 0xE0) {
        return Some(MagicResult::detected(MagicFileType::Mp3, 90, len));
    }

    // FLAC: fLaC
    if data.starts_with(b"fLaC") {
        return Some(MagicResult::detected(MagicFileType::Flac, 100, len));
    }

    // OGG: OggS
    if data.starts_with(b"OggS") {
        return Some(MagicResult::detected(MagicFileType::Ogg, 100, len));
    }

    // WAV: RIFF....WAVE
    if data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WAVE") {
        return Some(MagicResult::detected(MagicFileType::Wav, 100, len));
    }

    // AIFF: FORM....AIFF
    if data.starts_with(b"FORM") && data.get(8..12) == Some(b"AIFF") {
        return Some(MagicResult::detected(MagicFileType::Aiff, 100, len));
    }

    // MP4/M4A/MOV: ftyp-based detection
    if data.get(4..8) == Some(b"ftyp") {
        match data.get(8..12) {
            // Video brands
            Some(b"isom") | Some(b"iso2") | Some(b"mp41") | Some(b"mp42") | Some(b"avc1")
            | Some(b"dash") => {
                return Some(MagicResult::detected(MagicFileType::Mp4, 100, len));
            }
            // QuickTime
            Some(b"qt  ") => {
                return Some(MagicResult::detected(MagicFileType::Mov, 100, len));
            }
            // M4A (audio)
            Some(b"M4A ") | Some(b"M4B ") => {
                return Some(MagicResult::detected(MagicFileType::M4a, 100, len));
            }
            _ => {}
        }
    }

    // WebM/MKV: 1A 45 DF A3 (EBML)
    if data.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        // Both WebM and MKV use EBML container
        // Would need to parse further to distinguish, default to MKV
        return Some(MagicResult::detected(MagicFileType::Mkv, 90, len));
    }

    // AVI: RIFF....AVI
    if data.starts_with(b"RIFF") && data.get(8..12) == Some(b"AVI ") {
        return Some(MagicResult::detected(MagicFileType::Avi, 100, len));
    }

    None
}

// ============================================================================
// Data Format Detection
// ============================================================================

/// Detect data format file types from magic bytes
pub(crate) fn detect_data(data: &[u8]) -> Option<MagicResult> {
    let len = data.len();

    // SQLite: SQLite format 3\0
    if data.starts_with(b"SQLite format 3\0") {
        return Some(MagicResult::detected(MagicFileType::Sqlite, 100, len));
    }

    // XML: <?xml or BOM + <?xml
    // UTF-8 BOM + <?xml
    if data.starts_with(&[0xEF, 0xBB, 0xBF]) && data.get(3..8) == Some(b"<?xml") {
        return Some(MagicResult::detected(MagicFileType::Xml, 90, len));
    }
    // UTF-16 BE BOM
    if data.starts_with(&[0xFE, 0xFF]) {
        return Some(MagicResult::detected(MagicFileType::Xml, 90, len));
    }
    // UTF-16 LE BOM
    if data.starts_with(&[0xFF, 0xFE]) {
        return Some(MagicResult::detected(MagicFileType::Xml, 90, len));
    }
    // Without BOM
    if data.starts_with(b"<?xml") {
        return Some(MagicResult::detected(MagicFileType::Xml, 100, len));
    }

    None
}

// ============================================================================
// Script Detection
// ============================================================================

/// Detect script file types from shebang
pub(crate) fn detect_script(data: &[u8]) -> Option<MagicResult> {
    let len = data.len();

    // Shebang: #!
    if !data.starts_with(b"#!") {
        return None;
    }

    // Find the interpreter (get bytes after #!)
    let shebang_data = data.get(2..)?;
    let line_end = shebang_data
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(shebang_data.len().min(126));
    let shebang = shebang_data.get(..line_end)?;

    // Convert to string for easier matching
    let s = std::str::from_utf8(shebang).ok()?.trim();

    if s.contains("bash") || s.contains("/sh") || s.ends_with("sh") {
        return Some(MagicResult::detected(MagicFileType::ShellScript, 100, len));
    }
    if s.contains("python") {
        return Some(MagicResult::detected(MagicFileType::PythonScript, 100, len));
    }
    if s.contains("node") {
        return Some(MagicResult::detected(MagicFileType::NodeScript, 100, len));
    }
    if s.contains("ruby") {
        return Some(MagicResult::detected(MagicFileType::RubyScript, 100, len));
    }
    if s.contains("perl") {
        return Some(MagicResult::detected(MagicFileType::PerlScript, 100, len));
    }

    // Generic shebang - assume shell
    Some(MagicResult::detected(MagicFileType::ShellScript, 80, len))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ----------------------------------------
    // Image Detection Tests
    // ----------------------------------------

    #[test]
    fn test_png_detection() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];
        let result = detect_image(&png).expect("PNG should be detected");
        assert_eq!(result.file_type, Some(MagicFileType::Png));
        assert_eq!(result.confidence, 100);
    }

    #[test]
    fn test_jpeg_detection() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46];
        let result = detect_image(&jpeg).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Jpeg));
    }

    #[test]
    fn test_gif_detection() {
        let gif87 = b"GIF87a\x00\x00";
        let result = detect_image(gif87).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Gif));

        let gif89 = b"GIF89a\x00\x00";
        let result = detect_image(gif89).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Gif));
    }

    #[test]
    fn test_webp_detection() {
        let webp = b"RIFF\x00\x00\x00\x00WEBP";
        let result = detect_image(webp).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::WebP));
    }

    #[test]
    fn test_bmp_detection() {
        let bmp = [0x42, 0x4D, 0x00, 0x00];
        let result = detect_image(&bmp).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Bmp));
    }

    #[test]
    fn test_tiff_detection() {
        // Little-endian
        let tiff_le = [0x49, 0x49, 0x2A, 0x00];
        let result = detect_image(&tiff_le).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Tiff));

        // Big-endian
        let tiff_be = [0x4D, 0x4D, 0x00, 0x2A];
        let result = detect_image(&tiff_be).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Tiff));
    }

    #[test]
    fn test_ico_detection() {
        let ico = [0x00, 0x00, 0x01, 0x00];
        let result = detect_image(&ico).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Ico));
    }

    #[test]
    fn test_image_not_found() {
        let data = b"not an image";
        assert!(detect_image(data).is_none());
    }

    // ----------------------------------------
    // Archive Detection Tests
    // ----------------------------------------

    #[test]
    fn test_zip_detection() {
        let zip = [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00];
        let result = detect_archive(&zip).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::ZipArchive));
    }

    #[test]
    fn test_gzip_detection() {
        let gzip = [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = detect_archive(&gzip).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Gzip));
    }

    #[test]
    fn test_bzip2_detection() {
        let bzip2 = b"BZh91AY&SY";
        let result = detect_archive(bzip2).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Bzip2));
    }

    #[test]
    fn test_xz_detection() {
        let xz = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00];
        let result = detect_archive(&xz).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Xz));
    }

    #[test]
    fn test_7z_detection() {
        let sevenz = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x00];
        let result = detect_archive(&sevenz).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::SevenZip));
    }

    #[test]
    fn test_rar_detection() {
        let rar = b"Rar!\x1A\x07\x00";
        let result = detect_archive(rar).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Rar));
    }

    #[test]
    fn test_zstd_detection() {
        let zstd = [0x28, 0xB5, 0x2F, 0xFD, 0x00];
        let result = detect_archive(&zstd).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Zstd));
    }

    #[test]
    fn test_tar_detection() {
        let mut tar_file = vec![0u8; 262];
        if let Some(slice) = tar_file.get_mut(257..262) {
            slice.copy_from_slice(b"ustar");
        }
        let result = detect_archive(&tar_file).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Tar));
    }

    #[test]
    fn test_archive_not_found() {
        let data = b"not an archive";
        assert!(detect_archive(data).is_none());
    }

    // ----------------------------------------
    // Executable Detection Tests
    // ----------------------------------------

    #[test]
    fn test_elf_detection() {
        let elf = [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
        let result = detect_executable(&elf).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Elf));
    }

    #[test]
    fn test_pe_detection() {
        let pe = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        let result = detect_executable(&pe).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Pe));
    }

    #[test]
    fn test_macho_detection() {
        // 64-bit little-endian
        let macho64 = [0xCF, 0xFA, 0xED, 0xFE, 0x07, 0x00, 0x00, 0x01];
        let result = detect_executable(&macho64).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::MachO));

        // 32-bit big-endian
        let macho32 = [0xFE, 0xED, 0xFA, 0xCE, 0x00, 0x00, 0x00, 0x00];
        let result = detect_executable(&macho32).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::MachO));
    }

    #[test]
    fn test_macho_fat_detection() {
        let fat = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02];
        let result = detect_executable(&fat).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::MachOFat));
    }

    #[test]
    fn test_wasm_detection() {
        let wasm = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let result = detect_executable(&wasm).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Wasm));
    }

    #[test]
    fn test_executable_not_found() {
        let data = b"not an executable";
        assert!(detect_executable(data).is_none());
    }

    // ----------------------------------------
    // Document Detection Tests
    // ----------------------------------------

    #[test]
    fn test_pdf_detection() {
        let pdf = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3";
        let result = detect_document(pdf).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Pdf));
    }

    #[test]
    fn test_rtf_detection() {
        let rtf = b"{\\rtf1\\ansi";
        let result = detect_document(rtf).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Rtf));
    }

    #[test]
    fn test_document_not_found() {
        let data = b"not a document";
        assert!(detect_document(data).is_none());
    }

    // ----------------------------------------
    // Media Detection Tests
    // ----------------------------------------

    #[test]
    fn test_mp3_id3_detection() {
        let mp3 = b"ID3\x04\x00\x00\x00\x00\x00\x00";
        let result = detect_media(mp3).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Mp3));
    }

    #[test]
    fn test_mp3_sync_detection() {
        let mp3 = [0xFF, 0xFB, 0x90, 0x00];
        let result = detect_media(&mp3).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Mp3));
        assert_eq!(result.confidence, 90);
    }

    #[test]
    fn test_flac_detection() {
        let flac = b"fLaC\x00\x00\x00\x22";
        let result = detect_media(flac).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Flac));
    }

    #[test]
    fn test_ogg_detection() {
        let ogg = b"OggS\x00\x02";
        let result = detect_media(ogg).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Ogg));
    }

    #[test]
    fn test_wav_detection() {
        let wav = b"RIFF\x00\x00\x00\x00WAVEfmt ";
        let result = detect_media(wav).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Wav));
    }

    #[test]
    fn test_aiff_detection() {
        let aiff = b"FORM\x00\x00\x00\x00AIFF";
        let result = detect_media(aiff).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Aiff));
    }

    #[test]
    fn test_mp4_detection() {
        let mp4 = b"\x00\x00\x00\x00ftypisom";
        let result = detect_media(mp4).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Mp4));
    }

    #[test]
    fn test_mov_detection() {
        let mov = b"\x00\x00\x00\x00ftypqt  ";
        let result = detect_media(mov).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Mov));
    }

    #[test]
    fn test_m4a_detection() {
        let m4a = b"\x00\x00\x00\x00ftypM4A ";
        let result = detect_media(m4a).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::M4a));
    }

    #[test]
    fn test_mkv_detection() {
        let mkv = [0x1A, 0x45, 0xDF, 0xA3, 0x00];
        let result = detect_media(&mkv).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Mkv));
    }

    #[test]
    fn test_avi_detection() {
        let avi = b"RIFF\x00\x00\x00\x00AVI LIST";
        let result = detect_media(avi).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Avi));
    }

    #[test]
    fn test_media_not_found() {
        let data = b"not media";
        assert!(detect_media(data).is_none());
    }

    // ----------------------------------------
    // Data Detection Tests
    // ----------------------------------------

    #[test]
    fn test_sqlite_detection() {
        let sqlite = b"SQLite format 3\0\x10\x00\x01\x01";
        let result = detect_data(sqlite).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Sqlite));
    }

    #[test]
    fn test_xml_detection() {
        let xml = b"<?xml version=\"1.0\"?>";
        let result = detect_data(xml).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Xml));
    }

    #[test]
    fn test_xml_with_utf8_bom() {
        let xml = b"\xEF\xBB\xBF<?xml version=\"1.0\"?>";
        let result = detect_data(xml).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::Xml));
    }

    #[test]
    fn test_data_not_found() {
        let data = b"not data format";
        assert!(detect_data(data).is_none());
    }

    // ----------------------------------------
    // Script Detection Tests
    // ----------------------------------------

    #[test]
    fn test_shell_script_detection() {
        let sh = b"#!/bin/bash\necho hello";
        let result = detect_script(sh).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::ShellScript));
    }

    #[test]
    fn test_sh_script_detection() {
        let sh = b"#!/bin/sh\necho hello";
        let result = detect_script(sh).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::ShellScript));
    }

    #[test]
    fn test_python_script_detection() {
        let py = b"#!/usr/bin/env python3\nprint('hello')";
        let result = detect_script(py).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::PythonScript));
    }

    #[test]
    fn test_node_script_detection() {
        let node = b"#!/usr/bin/env node\nconsole.log('hi')";
        let result = detect_script(node).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::NodeScript));
    }

    #[test]
    fn test_ruby_script_detection() {
        let ruby = b"#!/usr/bin/ruby\nputs 'hello'";
        let result = detect_script(ruby).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::RubyScript));
    }

    #[test]
    fn test_perl_script_detection() {
        let perl = b"#!/usr/bin/perl\nprint 'hello'";
        let result = detect_script(perl).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::PerlScript));
    }

    #[test]
    fn test_generic_shebang() {
        let generic = b"#!/usr/bin/env unknown\n";
        let result = detect_script(generic).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::ShellScript));
        assert_eq!(result.confidence, 80);
    }

    #[test]
    fn test_shebang_no_newline() {
        let sh = b"#!/bin/bash";
        let result = detect_script(sh).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::ShellScript));
    }

    #[test]
    fn test_script_not_found() {
        let data = b"not a script";
        assert!(detect_script(data).is_none());
    }

    // ----------------------------------------
    // Adversarial Tests
    // ----------------------------------------

    #[test]
    fn test_adversarial_truncated_png() {
        // Only first 4 bytes of PNG header
        let truncated = [0x89, 0x50, 0x4E, 0x47];
        assert!(detect_image(&truncated).is_none());
    }

    #[test]
    fn test_adversarial_near_miss_png() {
        // Off-by-one in PNG signature
        let near_miss = [0x88, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert!(detect_image(&near_miss).is_none());
    }

    #[test]
    fn test_adversarial_null_prefix() {
        // Null bytes before PNG header
        let null_prefix = [0x00, 0x00, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let result = detect_image(&null_prefix);
        // Should NOT detect as PNG (could detect as ICO prefix though)
        assert!(
            result.is_none()
                || result.expect("detection should succeed").file_type != Some(MagicFileType::Png)
        );
    }

    #[test]
    fn test_adversarial_tar_too_short() {
        // TAR detection requires offset 257, this is too short
        let short = vec![0u8; 256];
        assert!(detect_archive(&short).is_none());
    }

    #[test]
    fn test_adversarial_shebang_with_space() {
        // Space after #!
        let sh = b"#! /bin/sh\n";
        let result = detect_script(sh).expect("detection should succeed");
        assert_eq!(result.file_type, Some(MagicFileType::ShellScript));
    }

    #[test]
    fn test_adversarial_all_0xff_not_jpeg() {
        // All 0xFF - JPEG needs FF D8 FF
        let all_ff = [0xFFu8; 64];
        assert!(detect_image(&all_ff).is_none());
    }

    #[test]
    fn test_adversarial_all_zeros() {
        // All zeros - should not match anything dangerous
        let zeros = [0x00u8; 64];
        assert!(detect_executable(&zeros).is_none());
        assert!(detect_archive(&zeros).is_none());
        assert!(detect_script(&zeros).is_none());
    }
}
