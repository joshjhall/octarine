//! Magic byte detection types
//!
//! Core types for file type identification via magic bytes.

use crate::primitives::data::paths::FileCategory;

/// Specific file type detected by magic bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MagicFileType {
    // Images
    /// PNG image format
    Png,
    /// JPEG image format
    Jpeg,
    /// GIF image format
    Gif,
    /// BMP image format
    Bmp,
    /// WebP image format
    WebP,
    /// TIFF image format
    Tiff,
    /// ICO icon format
    Ico,
    /// HEIC image format
    Heic,
    /// AVIF image format
    Avif,

    // Documents
    /// PDF document format
    Pdf,
    /// RTF document format
    Rtf,

    // Office (ZIP-based, detected as ZIP then refined)
    /// ZIP archive (also used for OOXML/ODF documents)
    ZipArchive,

    // Archives
    /// Gzip compressed file
    Gzip,
    /// Bzip2 compressed file
    Bzip2,
    /// XZ compressed file
    Xz,
    /// 7-Zip archive
    SevenZip,
    /// RAR archive
    Rar,
    /// TAR archive
    Tar,
    /// Zstandard compressed file
    Zstd,

    // Executables
    /// ELF executable (Linux/Unix)
    Elf,
    /// Mach-O executable (macOS)
    MachO,
    /// Mach-O fat/universal binary (macOS)
    MachOFat,
    /// PE executable (Windows)
    Pe,

    // Audio
    /// MP3 audio format
    Mp3,
    /// FLAC audio format
    Flac,
    /// Ogg audio format
    Ogg,
    /// WAV audio format
    Wav,
    /// AIFF audio format
    Aiff,
    /// M4A audio format
    M4a,

    // Video
    /// MP4 video format
    Mp4,
    /// WebM video format
    WebM,
    /// Matroska video format
    Mkv,
    /// AVI video format
    Avi,
    /// QuickTime video format
    Mov,

    // Data
    /// SQLite database file
    Sqlite,
    /// XML document
    Xml,

    // Scripts (detected by shebang)
    /// Shell script (bash, sh, etc.)
    ShellScript,
    /// Python script
    PythonScript,
    /// Node.js script
    NodeScript,
    /// Ruby script
    RubyScript,
    /// Perl script
    PerlScript,

    // Other
    /// WebAssembly binary
    Wasm,
}

impl MagicFileType {
    /// Convert to the broader FileCategory
    #[must_use]
    pub fn to_category(self) -> FileCategory {
        match self {
            // Images
            Self::Png
            | Self::Jpeg
            | Self::Gif
            | Self::Bmp
            | Self::WebP
            | Self::Tiff
            | Self::Ico
            | Self::Heic
            | Self::Avif => FileCategory::Image,

            // Documents
            Self::Pdf | Self::Rtf => FileCategory::Document,

            // Archives
            Self::ZipArchive
            | Self::Gzip
            | Self::Bzip2
            | Self::Xz
            | Self::SevenZip
            | Self::Rar
            | Self::Tar
            | Self::Zstd => FileCategory::Archive,

            // Executables
            Self::Elf | Self::MachO | Self::MachOFat | Self::Pe | Self::Wasm => {
                FileCategory::Executable
            }

            // Audio
            Self::Mp3 | Self::Flac | Self::Ogg | Self::Wav | Self::Aiff | Self::M4a => {
                FileCategory::Audio
            }

            // Video
            Self::Mp4 | Self::WebM | Self::Mkv | Self::Avi | Self::Mov => FileCategory::Video,

            // Data
            Self::Sqlite | Self::Xml => FileCategory::Data,

            // Scripts
            Self::ShellScript
            | Self::PythonScript
            | Self::NodeScript
            | Self::RubyScript
            | Self::PerlScript => FileCategory::Script,
        }
    }

    /// Get the typical file extension for this type
    #[must_use]
    pub fn typical_extension(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpg",
            Self::Gif => "gif",
            Self::Bmp => "bmp",
            Self::WebP => "webp",
            Self::Tiff => "tiff",
            Self::Ico => "ico",
            Self::Heic => "heic",
            Self::Avif => "avif",
            Self::Pdf => "pdf",
            Self::Rtf => "rtf",
            Self::ZipArchive => "zip",
            Self::Gzip => "gz",
            Self::Bzip2 => "bz2",
            Self::Xz => "xz",
            Self::SevenZip => "7z",
            Self::Rar => "rar",
            Self::Tar => "tar",
            Self::Zstd => "zst",
            Self::Elf => "elf",
            Self::MachO | Self::MachOFat => "macho",
            Self::Pe => "exe",
            Self::Mp3 => "mp3",
            Self::Flac => "flac",
            Self::Ogg => "ogg",
            Self::Wav => "wav",
            Self::Aiff => "aiff",
            Self::M4a => "m4a",
            Self::Mp4 => "mp4",
            Self::WebM => "webm",
            Self::Mkv => "mkv",
            Self::Avi => "avi",
            Self::Mov => "mov",
            Self::Sqlite => "sqlite",
            Self::Xml => "xml",
            Self::ShellScript => "sh",
            Self::PythonScript => "py",
            Self::NodeScript => "js",
            Self::RubyScript => "rb",
            Self::PerlScript => "pl",
            Self::Wasm => "wasm",
        }
    }

    /// Get the MIME type for this file type
    #[must_use]
    pub fn mime_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Gif => "image/gif",
            Self::Bmp => "image/bmp",
            Self::WebP => "image/webp",
            Self::Tiff => "image/tiff",
            Self::Ico => "image/x-icon",
            Self::Heic => "image/heic",
            Self::Avif => "image/avif",
            Self::Pdf => "application/pdf",
            Self::Rtf => "application/rtf",
            Self::ZipArchive => "application/zip",
            Self::Gzip => "application/gzip",
            Self::Bzip2 => "application/x-bzip2",
            Self::Xz => "application/x-xz",
            Self::SevenZip => "application/x-7z-compressed",
            Self::Rar => "application/vnd.rar",
            Self::Tar => "application/x-tar",
            Self::Zstd => "application/zstd",
            Self::Elf => "application/x-executable",
            Self::MachO | Self::MachOFat => "application/x-mach-binary",
            Self::Pe => "application/x-dosexec",
            Self::Mp3 => "audio/mpeg",
            Self::Flac => "audio/flac",
            Self::Ogg => "audio/ogg",
            Self::Wav => "audio/wav",
            Self::Aiff => "audio/aiff",
            Self::M4a => "audio/mp4",
            Self::Mp4 => "video/mp4",
            Self::WebM => "video/webm",
            Self::Mkv => "video/x-matroska",
            Self::Avi => "video/x-msvideo",
            Self::Mov => "video/quicktime",
            Self::Sqlite => "application/x-sqlite3",
            Self::Xml => "application/xml",
            Self::ShellScript => "application/x-sh",
            Self::PythonScript => "text/x-python",
            Self::NodeScript => "application/javascript",
            Self::RubyScript => "application/x-ruby",
            Self::PerlScript => "application/x-perl",
            Self::Wasm => "application/wasm",
        }
    }
}

/// Result of magic byte detection
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicResult {
    /// Detected file type (None if unknown)
    pub file_type: Option<MagicFileType>,

    /// Confidence level (0-100)
    pub confidence: u8,

    /// Number of bytes examined
    pub bytes_examined: usize,
}

impl MagicResult {
    /// Create a result for an unknown file type
    #[must_use]
    pub fn unknown(bytes_examined: usize) -> Self {
        Self {
            file_type: None,
            confidence: 0,
            bytes_examined,
        }
    }

    /// Create a result for a detected file type
    #[must_use]
    pub fn detected(file_type: MagicFileType, confidence: u8, bytes_examined: usize) -> Self {
        Self {
            file_type: Some(file_type),
            confidence,
            bytes_examined,
        }
    }

    /// Check if a file type was detected
    #[must_use]
    pub fn is_detected(&self) -> bool {
        self.file_type.is_some()
    }

    /// Get the FileCategory if detected
    #[must_use]
    pub fn category(&self) -> Option<FileCategory> {
        self.file_type.map(|ft| ft.to_category())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_magic_file_type_to_category() {
        assert_eq!(MagicFileType::Png.to_category(), FileCategory::Image);
        assert_eq!(MagicFileType::Pdf.to_category(), FileCategory::Document);
        assert_eq!(
            MagicFileType::ZipArchive.to_category(),
            FileCategory::Archive
        );
        assert_eq!(MagicFileType::Elf.to_category(), FileCategory::Executable);
        assert_eq!(MagicFileType::Mp3.to_category(), FileCategory::Audio);
        assert_eq!(MagicFileType::Mp4.to_category(), FileCategory::Video);
        assert_eq!(
            MagicFileType::ShellScript.to_category(),
            FileCategory::Script
        );
    }

    #[test]
    fn test_typical_extension() {
        assert_eq!(MagicFileType::Png.typical_extension(), "png");
        assert_eq!(MagicFileType::Jpeg.typical_extension(), "jpg");
        assert_eq!(MagicFileType::Pdf.typical_extension(), "pdf");
    }

    #[test]
    fn test_mime_type() {
        assert_eq!(MagicFileType::Png.mime_type(), "image/png");
        assert_eq!(MagicFileType::Pdf.mime_type(), "application/pdf");
        assert_eq!(MagicFileType::Mp4.mime_type(), "video/mp4");
    }

    #[test]
    fn test_magic_result_unknown() {
        let result = MagicResult::unknown(64);
        assert!(!result.is_detected());
        assert_eq!(result.confidence, 0);
        assert_eq!(result.bytes_examined, 64);
        assert!(result.category().is_none());
    }

    #[test]
    fn test_magic_result_detected() {
        let result = MagicResult::detected(MagicFileType::Png, 100, 8);
        assert!(result.is_detected());
        assert_eq!(result.file_type, Some(MagicFileType::Png));
        assert_eq!(result.confidence, 100);
        assert_eq!(result.category(), Some(FileCategory::Image));
    }
}
