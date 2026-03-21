//! File type shortcuts
//!
//! Convenience functions for checking file types by extension.

use crate::primitives::data::paths::FiletypeBuilder;

use super::super::PathBuilder;

// ============================================================
// FILE TYPE SHORTCUTS
// ============================================================

/// Check if file is an image
pub fn is_image_file(path: &str) -> bool {
    FiletypeBuilder::new().is_image(path)
}

/// Check if file is audio
pub fn is_audio_file(path: &str) -> bool {
    FiletypeBuilder::new().is_audio(path)
}

/// Check if file is video
pub fn is_video_file(path: &str) -> bool {
    FiletypeBuilder::new().is_video(path)
}

/// Check if file is any media type
pub fn is_media_file(path: &str) -> bool {
    FiletypeBuilder::new().is_media(path)
}

/// Check if file is a document
pub fn is_document_file(path: &str) -> bool {
    FiletypeBuilder::new().is_document(path)
}

/// Check if file is source code
pub fn is_code_file(path: &str) -> bool {
    FiletypeBuilder::new().is_code(path)
}

/// Check if file is a config file
pub fn is_config_file(path: &str) -> bool {
    FiletypeBuilder::new().is_config(path)
}

/// Check if file is an executable
pub fn is_executable_file(path: &str) -> bool {
    FiletypeBuilder::new().is_executable(path)
}

/// Check if file is security-sensitive (credentials, keys, etc.)
pub fn is_security_sensitive_file(path: &str) -> bool {
    PathBuilder::new().is_security_sensitive(path)
}

// ============================================================
// ADDITIONAL FILE TYPE SHORTCUTS
// ============================================================

/// Check if file is an archive (zip, tar, etc.)
pub fn is_archive_file(path: &str) -> bool {
    use super::super::FiletypeBuilder;
    FiletypeBuilder::new().is_archive(path)
}

/// Check if file is a script (sh, bash, ps1, etc.)
pub fn is_script_file(path: &str) -> bool {
    use super::super::FiletypeBuilder;
    FiletypeBuilder::new().is_script(path)
}

/// Check if file is a font
pub fn is_font_file(path: &str) -> bool {
    use super::super::FiletypeBuilder;
    FiletypeBuilder::new().is_font(path)
}

/// Check if file is a database
pub fn is_database_file(path: &str) -> bool {
    use super::super::FiletypeBuilder;
    FiletypeBuilder::new().is_database(path)
}

/// Check if file is a log file
pub fn is_log_file(path: &str) -> bool {
    use super::super::FiletypeBuilder;
    FiletypeBuilder::new().is_log(path)
}

/// Check if file is a backup file
pub fn is_backup_file(path: &str) -> bool {
    use super::super::FiletypeBuilder;
    FiletypeBuilder::new().is_backup(path)
}

/// Check if file is a temporary file
pub fn is_temp_file(path: &str) -> bool {
    use super::super::FiletypeBuilder;
    FiletypeBuilder::new().is_temporary(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_file_type_shortcuts() {
        assert!(is_image_file("photo.jpg"));
        assert!(is_code_file("main.rs"));
        assert!(is_config_file("config.json"));
        assert!(is_security_sensitive_file(".env"));
    }
}
