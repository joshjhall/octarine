//! File type detection based on extension and filename patterns
//!
//! Pure detection functions with no observe dependencies.
//! Used for identifying file types for security decisions.
//!
//! # Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Performance
//!
//! Extension lookups use `HashSet` for O(1) average case.
//! Sets are lazily initialized once via `once_cell::sync::Lazy`.

use super::super::types::FileCategory;
use once_cell::sync::Lazy;
use std::collections::HashSet;

// ============================================================================
// Extension Sets (O(1) lookup)
// ============================================================================

static IMAGE_EXTENSIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "jpg", "jpeg", "png", "gif", "bmp", "webp", "svg", "ico", "tiff", "tif", "heic", "heif",
        "raw", "cr2", "nef",
    ]
    .into_iter()
    .collect()
});

static AUDIO_EXTENSIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "mp3", "wav", "flac", "aac", "ogg", "wma", "m4a", "opus", "aiff",
    ]
    .into_iter()
    .collect()
});

static VIDEO_EXTENSIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v", "mpeg", "mpg", "3gp",
    ]
    .into_iter()
    .collect()
});

static DOCUMENT_EXTENSIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    ["pdf", "doc", "docx", "odt", "rtf", "tex", "wpd"]
        .into_iter()
        .collect()
});

static SPREADSHEET_EXTENSIONS: Lazy<HashSet<&'static str>> =
    Lazy::new(|| ["xls", "xlsx", "ods", "csv", "tsv"].into_iter().collect());

// Note: Apple Keynote uses .key extension but that conflicts with cryptographic keys
// We prioritize security: .key goes to CREDENTIAL_EXTENSIONS
static PRESENTATION_EXTENSIONS: Lazy<HashSet<&'static str>> =
    Lazy::new(|| ["ppt", "pptx", "odp"].into_iter().collect());

static TEXT_EXTENSIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    ["txt", "md", "markdown", "rst", "log", "nfo"]
        .into_iter()
        .collect()
});

static SOURCE_CODE_EXTENSIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "rs", "py", "js", "ts", "jsx", "tsx", "java", "c", "cpp", "cc", "cxx", "h", "hpp", "go",
        "rb", "php", "swift", "kt", "scala", "cs", "fs", "vb", "m", "mm", "r", "jl", "lua", "pl",
        "pm", "ex", "exs", "erl", "hrl", "hs", "elm", "clj", "cljs",
    ]
    .into_iter()
    .collect()
});

static SCRIPT_EXTENSIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "sh", "bash", "zsh", "fish", "ps1", "psm1", "bat", "cmd", "vbs", "awk", "sed",
    ]
    .into_iter()
    .collect()
});

static CONFIG_EXTENSIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "json",
        "yaml",
        "yml",
        "toml",
        "ini",
        "cfg",
        "conf",
        "config",
        "xml",
        "properties",
    ]
    .into_iter()
    .collect()
});

static DATA_EXTENSIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "sql", "db", "sqlite", "sqlite3", "mdb", "parquet", "avro", "proto", "graphql",
    ]
    .into_iter()
    .collect()
});

static ARCHIVE_EXTENSIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    ["zip", "tar", "rar", "7z", "iso", "dmg"]
        .into_iter()
        .collect()
});

static COMPRESSED_EXTENSIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    ["gz", "gzip", "bz2", "xz", "lz", "lzma", "zst", "br"]
        .into_iter()
        .collect()
});

static EXECUTABLE_EXTENSIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    ["exe", "msi", "app", "deb", "rpm", "apk", "ipa", "appimage"]
        .into_iter()
        .collect()
});

static LIBRARY_EXTENSIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    ["dll", "so", "dylib", "a", "lib", "o"]
        .into_iter()
        .collect()
});

// Note: These are private key / credential file extensions
// Certificate extensions (crt, cer, pem) are handled separately as they may be public
static CREDENTIAL_EXTENSIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    ["key", "p12", "pfx", "jks", "keystore", "ppk"]
        .into_iter()
        .collect()
});

// Certificate extensions - these can be public (certs) or private (private keys in .pem)
// For detection purposes, we categorize these as Certificate since that's most common
static CERTIFICATE_EXTENSIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    ["crt", "cer", "pem", "der", "ca-bundle", "csr"]
        .into_iter()
        .collect()
});

// ============================================================================
// Dispatch Tables
// ============================================================================

// Each entry pairs a membership set with the FileCategory it maps to.
// Order matters — security-sensitive categories are checked first so that
// ambiguous extensions like `.key` resolve to Credential rather than a
// benign category further down the list.
type ExtensionRule = (&'static Lazy<HashSet<&'static str>>, FileCategory);

static EXTENSION_RULES: &[ExtensionRule] = &[
    (&CREDENTIAL_EXTENSIONS, FileCategory::Credential),
    (&CERTIFICATE_EXTENSIONS, FileCategory::Certificate),
    (&EXECUTABLE_EXTENSIONS, FileCategory::Executable),
    (&LIBRARY_EXTENSIONS, FileCategory::Library),
    (&IMAGE_EXTENSIONS, FileCategory::Image),
    (&AUDIO_EXTENSIONS, FileCategory::Audio),
    (&VIDEO_EXTENSIONS, FileCategory::Video),
    (&DOCUMENT_EXTENSIONS, FileCategory::Document),
    (&SPREADSHEET_EXTENSIONS, FileCategory::Spreadsheet),
    (&PRESENTATION_EXTENSIONS, FileCategory::Presentation),
    (&TEXT_EXTENSIONS, FileCategory::Text),
    (&SOURCE_CODE_EXTENSIONS, FileCategory::SourceCode),
    (&SCRIPT_EXTENSIONS, FileCategory::Script),
    (&CONFIG_EXTENSIONS, FileCategory::Config),
    (&DATA_EXTENSIONS, FileCategory::Data),
    (&ARCHIVE_EXTENSIONS, FileCategory::Archive),
    (&COMPRESSED_EXTENSIONS, FileCategory::Compressed),
];

// ============================================================================
// Detection Functions
// ============================================================================

/// Detect file category from path
///
/// Examines the filename and extension to determine the file category.
/// Checks special filename patterns first, then extension.
///
/// # Arguments
///
/// * `path` - Path to analyze (can be full path or just filename)
///
/// # Returns
///
/// `FileCategory` indicating the detected type
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::filetype::detect_file_category;
/// use octarine::primitives::paths::types::FileCategory;
///
/// assert_eq!(detect_file_category("photo.jpg"), FileCategory::Image);
/// assert_eq!(detect_file_category("main.rs"), FileCategory::SourceCode);
/// assert_eq!(detect_file_category(".env"), FileCategory::Credential);
/// ```
#[must_use]
pub fn detect_file_category(path: &str) -> FileCategory {
    // Check special filenames first
    if let Some(cat) = detect_by_filename(path) {
        return cat;
    }

    // Then check by extension
    if let Some(ext) = get_extension_lower(path) {
        return detect_by_extension(&ext);
    }

    FileCategory::Unknown
}

/// Get lowercase extension from path
///
/// # Arguments
///
/// * `path` - Path to extract extension from
///
/// # Returns
///
/// `Some(extension)` in lowercase, or `None` if no extension
fn get_extension_lower(path: &str) -> Option<String> {
    let filename = path.rsplit(['/', '\\']).next()?;
    let dot_pos = filename.rfind('.')?;
    let len = filename.len();

    // No extension if dot is at start (.hidden) or end (file.)
    // Using saturating_sub to avoid clippy::arithmetic_side_effects
    if dot_pos == 0 || dot_pos == len.saturating_sub(1) {
        return None;
    }

    // Safe: dot_pos < len and dot_pos+1 <= len (checked above)
    Some(filename.get(dot_pos.saturating_add(1)..)?.to_lowercase())
}

/// Detect category by extension
fn detect_by_extension(ext: &str) -> FileCategory {
    EXTENSION_RULES
        .iter()
        .find(|(set, _)| set.contains(ext))
        .map(|(_, cat)| *cat)
        .unwrap_or(FileCategory::Unknown)
}

// ============================================================================
// Filename Predicates
// ============================================================================
// Rule order in FILENAME_RULES matches the original if-chain so that
// overlapping cases resolve identically (e.g. `.htpasswd` matches the
// credential rule before the hidden-file rule, and `.env.local` matches
// the env rule before the hidden-file rule).

fn is_temporary_filename(lower: &str) -> bool {
    lower.ends_with('~')
        || lower.starts_with('#')
        || lower.ends_with(".tmp")
        || lower.ends_with(".temp")
        || lower.ends_with(".swp")
}

fn is_credential_filename(lower: &str) -> bool {
    lower.contains("password")
        || lower.contains("secret")
        || lower.contains("credential")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower == ".htpasswd"
        || lower == "shadow"
        || lower == "passwd"
}

fn is_ssh_key_filename(lower: &str) -> bool {
    lower.starts_with("id_") || lower == "authorized_keys" || lower == "known_hosts"
}

fn is_env_filename(lower: &str) -> bool {
    lower == ".env" || lower.starts_with(".env.")
}

// Dotfile with no secondary extension (e.g. `.bashrc`, not `.bash.bak`).
// Char-iterator form avoids `lower[1..]` which would trip clippy::indexing_slicing.
fn is_hidden_filename(lower: &str) -> bool {
    let mut chars = lower.chars();
    matches!(chars.next(), Some('.')) && !chars.any(|c| c == '.')
}

type FilenameRule = (fn(&str) -> bool, FileCategory);

static FILENAME_RULES: &[FilenameRule] = &[
    (is_temporary_filename, FileCategory::Temporary),
    (is_credential_filename, FileCategory::Credential),
    (is_ssh_key_filename, FileCategory::Key),
    (is_env_filename, FileCategory::Credential),
    (is_hidden_filename, FileCategory::Hidden),
];

/// Detect category by special filename patterns
fn detect_by_filename(path: &str) -> Option<FileCategory> {
    let filename = path.rsplit(['/', '\\']).next()?;
    let lower = filename.to_lowercase();
    FILENAME_RULES
        .iter()
        .find(|(pred, _)| pred(&lower))
        .map(|(_, cat)| *cat)
}

// ============================================================================
// Category Check Functions
// ============================================================================

/// Check if file is an image
#[must_use]
pub fn is_image(path: &str) -> bool {
    matches!(detect_file_category(path), FileCategory::Image)
}

/// Check if file is audio
#[must_use]
pub fn is_audio(path: &str) -> bool {
    matches!(detect_file_category(path), FileCategory::Audio)
}

/// Check if file is video
#[must_use]
pub fn is_video(path: &str) -> bool {
    matches!(detect_file_category(path), FileCategory::Video)
}

/// Check if file is any media type (image, audio, or video)
#[must_use]
pub fn is_media(path: &str) -> bool {
    matches!(
        detect_file_category(path),
        FileCategory::Image | FileCategory::Audio | FileCategory::Video
    )
}

/// Check if file is a document (including text, spreadsheets, presentations)
#[must_use]
pub fn is_document(path: &str) -> bool {
    matches!(
        detect_file_category(path),
        FileCategory::Document
            | FileCategory::Spreadsheet
            | FileCategory::Presentation
            | FileCategory::Text
    )
}

/// Check if file is source code or script
#[must_use]
pub fn is_code(path: &str) -> bool {
    matches!(
        detect_file_category(path),
        FileCategory::SourceCode | FileCategory::Script
    )
}

/// Check if file is an executable
#[must_use]
pub fn is_executable(path: &str) -> bool {
    matches!(detect_file_category(path), FileCategory::Executable)
}

/// Check if file is a library
#[must_use]
pub fn is_library(path: &str) -> bool {
    matches!(detect_file_category(path), FileCategory::Library)
}

/// Check if file is an archive or compressed
#[must_use]
pub fn is_archive(path: &str) -> bool {
    matches!(
        detect_file_category(path),
        FileCategory::Archive | FileCategory::Compressed
    )
}

/// Check if file is a configuration file
#[must_use]
pub fn is_config(path: &str) -> bool {
    matches!(detect_file_category(path), FileCategory::Config)
}

/// Check if file is a data file (databases, structured data)
#[must_use]
pub fn is_data(path: &str) -> bool {
    matches!(detect_file_category(path), FileCategory::Data)
}

/// Check if file is security-sensitive (credentials, keys, certs)
#[must_use]
pub fn is_security_sensitive(path: &str) -> bool {
    matches!(
        detect_file_category(path),
        FileCategory::Credential | FileCategory::Certificate | FileCategory::Key
    )
}

/// Check if file is hidden or temporary
#[must_use]
pub fn is_hidden_or_temp(path: &str) -> bool {
    matches!(
        detect_file_category(path),
        FileCategory::Hidden | FileCategory::Temporary
    )
}

/// Check if file is text-based (human-readable)
#[must_use]
pub fn is_text_based(path: &str) -> bool {
    matches!(
        detect_file_category(path),
        FileCategory::Text
            | FileCategory::SourceCode
            | FileCategory::Script
            | FileCategory::Config
            | FileCategory::Data
    )
}

// ============================================================================
// Extension Extraction
// ============================================================================

/// Find the file extension (lowercase)
///
/// # Arguments
///
/// * `path` - Path to extract extension from
///
/// # Returns
///
/// `Some(extension)` in lowercase, or `None` if no extension
#[must_use]
pub fn find_extension(path: &str) -> Option<String> {
    get_extension_lower(path)
}

/// Check if file has a specific extension (case-insensitive)
///
/// # Arguments
///
/// * `path` - Path to check
/// * `ext` - Extension to check for (without dot)
///
/// # Returns
///
/// `true` if the file has the specified extension
#[must_use]
pub fn is_extension_found(path: &str, ext: &str) -> bool {
    get_extension_lower(path)
        .map(|e| e.eq_ignore_ascii_case(ext))
        .unwrap_or(false)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ----------------------------------------
    // Image Detection
    // ----------------------------------------

    #[test]
    fn test_image_detection() {
        assert_eq!(detect_file_category("photo.jpg"), FileCategory::Image);
        assert_eq!(detect_file_category("photo.JPEG"), FileCategory::Image);
        assert_eq!(detect_file_category("icon.png"), FileCategory::Image);
        assert_eq!(detect_file_category("animation.gif"), FileCategory::Image);
        assert_eq!(detect_file_category("logo.svg"), FileCategory::Image);
        assert_eq!(detect_file_category("photo.webp"), FileCategory::Image);
    }

    #[test]
    fn test_is_image() {
        assert!(is_image("photo.jpg"));
        assert!(is_image("/path/to/image.PNG"));
        assert!(!is_image("document.pdf"));
        assert!(!is_image("song.mp3"));
    }

    // ----------------------------------------
    // Audio Detection
    // ----------------------------------------

    #[test]
    fn test_audio_detection() {
        assert_eq!(detect_file_category("song.mp3"), FileCategory::Audio);
        assert_eq!(detect_file_category("track.flac"), FileCategory::Audio);
        assert_eq!(detect_file_category("audio.wav"), FileCategory::Audio);
        assert_eq!(detect_file_category("music.ogg"), FileCategory::Audio);
    }

    #[test]
    fn test_is_audio() {
        assert!(is_audio("song.mp3"));
        assert!(is_audio("track.FLAC"));
        assert!(!is_audio("video.mp4"));
    }

    // ----------------------------------------
    // Video Detection
    // ----------------------------------------

    #[test]
    fn test_video_detection() {
        assert_eq!(detect_file_category("movie.mp4"), FileCategory::Video);
        assert_eq!(detect_file_category("clip.mkv"), FileCategory::Video);
        assert_eq!(detect_file_category("video.avi"), FileCategory::Video);
        assert_eq!(detect_file_category("stream.webm"), FileCategory::Video);
    }

    #[test]
    fn test_is_video() {
        assert!(is_video("movie.mp4"));
        assert!(is_video("clip.MKV"));
        assert!(!is_video("song.mp3"));
    }

    // ----------------------------------------
    // Media Detection
    // ----------------------------------------

    #[test]
    fn test_is_media() {
        assert!(is_media("photo.jpg"));
        assert!(is_media("song.mp3"));
        assert!(is_media("movie.mp4"));
        assert!(!is_media("document.pdf"));
        assert!(!is_media("code.rs"));
    }

    // ----------------------------------------
    // Document Detection
    // ----------------------------------------

    #[test]
    fn test_document_detection() {
        assert_eq!(detect_file_category("report.pdf"), FileCategory::Document);
        assert_eq!(detect_file_category("letter.doc"), FileCategory::Document);
        assert_eq!(detect_file_category("essay.docx"), FileCategory::Document);
    }

    #[test]
    fn test_spreadsheet_detection() {
        assert_eq!(detect_file_category("data.xls"), FileCategory::Spreadsheet);
        assert_eq!(
            detect_file_category("budget.xlsx"),
            FileCategory::Spreadsheet
        );
        assert_eq!(
            detect_file_category("export.csv"),
            FileCategory::Spreadsheet
        );
    }

    #[test]
    fn test_presentation_detection() {
        assert_eq!(
            detect_file_category("slides.ppt"),
            FileCategory::Presentation
        );
        assert_eq!(
            detect_file_category("deck.pptx"),
            FileCategory::Presentation
        );
        // Note: .key is in CREDENTIAL_EXTENSIONS (takes priority for security)
        // Use Apple Keynote's actual extension (.key) with care - it conflicts with crypto keys
        assert_eq!(
            detect_file_category("presentation.odp"),
            FileCategory::Presentation
        );
    }

    #[test]
    fn test_text_detection() {
        assert_eq!(detect_file_category("readme.txt"), FileCategory::Text);
        assert_eq!(detect_file_category("notes.md"), FileCategory::Text);
        assert_eq!(detect_file_category("doc.rst"), FileCategory::Text);
    }

    #[test]
    fn test_is_document() {
        assert!(is_document("report.pdf"));
        assert!(is_document("data.xlsx"));
        assert!(is_document("notes.txt"));
        assert!(!is_document("photo.jpg"));
        assert!(!is_document("code.rs"));
    }

    // ----------------------------------------
    // Code Detection
    // ----------------------------------------

    #[test]
    fn test_source_code_detection() {
        assert_eq!(detect_file_category("main.rs"), FileCategory::SourceCode);
        assert_eq!(detect_file_category("app.py"), FileCategory::SourceCode);
        assert_eq!(detect_file_category("index.js"), FileCategory::SourceCode);
        assert_eq!(detect_file_category("App.tsx"), FileCategory::SourceCode);
        assert_eq!(detect_file_category("Main.java"), FileCategory::SourceCode);
        assert_eq!(detect_file_category("helper.c"), FileCategory::SourceCode);
        assert_eq!(detect_file_category("util.go"), FileCategory::SourceCode);
    }

    #[test]
    fn test_script_detection() {
        assert_eq!(detect_file_category("install.sh"), FileCategory::Script);
        assert_eq!(detect_file_category("build.bash"), FileCategory::Script);
        assert_eq!(detect_file_category("deploy.ps1"), FileCategory::Script);
        assert_eq!(detect_file_category("setup.bat"), FileCategory::Script);
    }

    #[test]
    fn test_is_code() {
        assert!(is_code("main.rs"));
        assert!(is_code("script.sh"));
        assert!(is_code("app.py"));
        assert!(!is_code("config.json"));
        assert!(!is_code("photo.jpg"));
    }

    // ----------------------------------------
    // Config and Data Detection
    // ----------------------------------------

    #[test]
    fn test_config_detection() {
        assert_eq!(detect_file_category("config.json"), FileCategory::Config);
        assert_eq!(detect_file_category("settings.yaml"), FileCategory::Config);
        assert_eq!(detect_file_category("Cargo.toml"), FileCategory::Config);
        assert_eq!(detect_file_category("app.ini"), FileCategory::Config);
        assert_eq!(detect_file_category("pom.xml"), FileCategory::Config);
    }

    #[test]
    fn test_data_detection() {
        assert_eq!(detect_file_category("schema.sql"), FileCategory::Data);
        assert_eq!(detect_file_category("app.sqlite"), FileCategory::Data);
        assert_eq!(detect_file_category("data.parquet"), FileCategory::Data);
    }

    #[test]
    fn test_is_config() {
        assert!(is_config("config.json"));
        assert!(is_config("settings.yaml"));
        assert!(is_config("Cargo.toml"));
        assert!(!is_config("main.rs"));
    }

    #[test]
    fn test_is_data() {
        assert!(is_data("database.sql"));
        assert!(is_data("app.sqlite"));
        assert!(!is_data("config.json"));
    }

    // ----------------------------------------
    // Executable Detection
    // ----------------------------------------

    #[test]
    fn test_executable_detection() {
        assert_eq!(
            detect_file_category("program.exe"),
            FileCategory::Executable
        );
        assert_eq!(
            detect_file_category("installer.msi"),
            FileCategory::Executable
        );
        assert_eq!(detect_file_category("app.deb"), FileCategory::Executable);
        assert_eq!(
            detect_file_category("package.rpm"),
            FileCategory::Executable
        );
    }

    #[test]
    fn test_library_detection() {
        assert_eq!(detect_file_category("libfoo.so"), FileCategory::Library);
        assert_eq!(detect_file_category("helper.dll"), FileCategory::Library);
        assert_eq!(
            detect_file_category("framework.dylib"),
            FileCategory::Library
        );
        assert_eq!(detect_file_category("static.a"), FileCategory::Library);
    }

    #[test]
    fn test_is_executable() {
        assert!(is_executable("program.exe"));
        assert!(is_executable("installer.msi"));
        assert!(!is_executable("document.pdf"));
        assert!(!is_executable("script.sh")); // scripts are not "executables"
    }

    #[test]
    fn test_is_library() {
        assert!(is_library("libfoo.so"));
        assert!(is_library("helper.dll"));
        assert!(!is_library("program.exe"));
    }

    // ----------------------------------------
    // Archive Detection
    // ----------------------------------------

    #[test]
    fn test_archive_detection() {
        assert_eq!(detect_file_category("backup.zip"), FileCategory::Archive);
        assert_eq!(detect_file_category("archive.tar"), FileCategory::Archive);
        assert_eq!(detect_file_category("files.rar"), FileCategory::Archive);
        assert_eq!(detect_file_category("compressed.7z"), FileCategory::Archive);
    }

    #[test]
    fn test_compressed_detection() {
        assert_eq!(detect_file_category("data.gz"), FileCategory::Compressed);
        assert_eq!(detect_file_category("file.bz2"), FileCategory::Compressed);
        assert_eq!(detect_file_category("archive.xz"), FileCategory::Compressed);
        assert_eq!(
            detect_file_category("content.zst"),
            FileCategory::Compressed
        );
    }

    #[test]
    fn test_is_archive() {
        assert!(is_archive("backup.zip"));
        assert!(is_archive("data.tar"));
        assert!(is_archive("file.gz"));
        assert!(!is_archive("document.pdf"));
    }

    // ----------------------------------------
    // Security-Sensitive Detection
    // ----------------------------------------

    #[test]
    fn test_credential_by_extension() {
        assert_eq!(detect_file_category("server.key"), FileCategory::Credential);
        assert_eq!(
            detect_file_category("keystore.p12"),
            FileCategory::Credential
        );
        assert_eq!(detect_file_category("store.pfx"), FileCategory::Credential);
        assert_eq!(detect_file_category("java.jks"), FileCategory::Credential);
        assert_eq!(detect_file_category("putty.ppk"), FileCategory::Credential);
    }

    #[test]
    fn test_credential_by_name() {
        assert_eq!(detect_file_category(".env"), FileCategory::Credential);
        assert_eq!(detect_file_category(".env.local"), FileCategory::Credential);
        assert_eq!(
            detect_file_category("password.txt"),
            FileCategory::Credential
        );
        assert_eq!(
            detect_file_category("secrets.json"),
            FileCategory::Credential
        );
        assert_eq!(
            detect_file_category("api_key.txt"),
            FileCategory::Credential
        );
        assert_eq!(detect_file_category(".htpasswd"), FileCategory::Credential);
    }

    #[test]
    fn test_key_by_name() {
        assert_eq!(detect_file_category("id_rsa"), FileCategory::Key);
        assert_eq!(detect_file_category("id_ed25519"), FileCategory::Key);
        assert_eq!(detect_file_category("authorized_keys"), FileCategory::Key);
        assert_eq!(detect_file_category("known_hosts"), FileCategory::Key);
    }

    #[test]
    fn test_certificate_detection() {
        assert_eq!(
            detect_file_category("server.crt"),
            FileCategory::Certificate
        );
        assert_eq!(detect_file_category("ca.cer"), FileCategory::Certificate);
    }

    #[test]
    fn test_is_security_sensitive() {
        assert!(is_security_sensitive("server.key"));
        assert!(is_security_sensitive(".env"));
        assert!(is_security_sensitive("id_rsa"));
        assert!(is_security_sensitive("cert.pem")); // Certificate is security-sensitive
        assert!(is_security_sensitive("server.crt")); // Certificate is security-sensitive
        assert!(!is_security_sensitive("readme.txt"));
        assert!(!is_security_sensitive("config.json"));
    }

    // ----------------------------------------
    // Hidden and Temporary Detection
    // ----------------------------------------

    #[test]
    fn test_hidden_detection() {
        assert_eq!(detect_file_category(".gitignore"), FileCategory::Hidden);
        assert_eq!(detect_file_category(".bashrc"), FileCategory::Hidden);
        assert_eq!(detect_file_category(".config"), FileCategory::Hidden);
    }

    #[test]
    fn test_temporary_detection() {
        assert_eq!(detect_file_category("file.tmp"), FileCategory::Temporary);
        assert_eq!(detect_file_category("backup~"), FileCategory::Temporary);
        assert_eq!(detect_file_category("#autosave#"), FileCategory::Temporary);
        assert_eq!(detect_file_category("file.temp"), FileCategory::Temporary);
        assert_eq!(detect_file_category(".file.swp"), FileCategory::Temporary);
    }

    #[test]
    fn test_is_hidden_or_temp() {
        assert!(is_hidden_or_temp(".gitignore"));
        assert!(is_hidden_or_temp("file.tmp"));
        assert!(is_hidden_or_temp("backup~"));
        assert!(!is_hidden_or_temp("readme.txt"));
    }

    // ----------------------------------------
    // Text-Based Detection
    // ----------------------------------------

    #[test]
    fn test_is_text_based() {
        assert!(is_text_based("readme.txt"));
        assert!(is_text_based("main.rs"));
        assert!(is_text_based("config.json"));
        assert!(is_text_based("script.sh"));
        assert!(is_text_based("schema.sql"));
        assert!(!is_text_based("photo.jpg"));
        assert!(!is_text_based("video.mp4"));
        assert!(!is_text_based("archive.zip"));
    }

    // ----------------------------------------
    // Extension Functions
    // ----------------------------------------

    #[test]
    fn test_find_extension() {
        assert_eq!(find_extension("photo.JPG"), Some("jpg".to_string()));
        assert_eq!(find_extension("/path/to/file.rs"), Some("rs".to_string()));
        assert_eq!(
            find_extension("C:\\path\\file.TXT"),
            Some("txt".to_string())
        );
        assert_eq!(find_extension(".gitignore"), None);
        assert_eq!(find_extension("no_extension"), None);
        assert_eq!(find_extension("file."), None);
    }

    #[test]
    fn test_is_extension_found() {
        assert!(is_extension_found("photo.JPG", "jpg"));
        assert!(is_extension_found("photo.jpg", "JPG"));
        assert!(is_extension_found("/path/to/file.rs", "rs"));
        assert!(!is_extension_found("photo.png", "jpg"));
        assert!(!is_extension_found(".gitignore", "gitignore"));
    }

    // ----------------------------------------
    // Edge Cases
    // ----------------------------------------

    #[test]
    fn test_empty_path() {
        assert_eq!(detect_file_category(""), FileCategory::Unknown);
    }

    #[test]
    fn test_unknown_extension() {
        assert_eq!(detect_file_category("file.xyz123"), FileCategory::Unknown);
        assert_eq!(detect_file_category("random.qqq"), FileCategory::Unknown);
    }

    #[test]
    fn test_multiple_dots() {
        assert_eq!(
            detect_file_category("archive.tar.gz"),
            FileCategory::Compressed
        );
        assert_eq!(detect_file_category("file.backup.txt"), FileCategory::Text);
    }

    #[test]
    fn test_path_with_directory() {
        assert_eq!(
            detect_file_category("/usr/bin/program.exe"),
            FileCategory::Executable
        );
        assert_eq!(
            detect_file_category("C:\\Users\\file.doc"),
            FileCategory::Document
        );
        assert_eq!(
            detect_file_category("./src/main.rs"),
            FileCategory::SourceCode
        );
    }

    #[test]
    fn test_case_insensitive() {
        assert_eq!(detect_file_category("PHOTO.JPG"), FileCategory::Image);
        assert_eq!(detect_file_category("Document.PDF"), FileCategory::Document);
        assert_eq!(detect_file_category("CODE.RS"), FileCategory::SourceCode);
    }
}
