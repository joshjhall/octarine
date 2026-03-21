//! File type detection domain module
//!
//! Pure detection functions for identifying file types based on extension
//! and filename patterns. Answers "What kind of file is this?"
//!
//! # Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Features
//!
//! - **Extension-based detection**: Identifies file types by extension
//! - **Filename pattern detection**: Recognizes special files (.env, id_rsa, etc.)
//! - **Security-sensitive detection**: Identifies credentials, keys, certificates
//! - **Category checks**: Convenience functions for common file type groups
//!
//! # Usage
//!
//! ## Using FiletypeBuilder (recommended)
//!
//! ```ignore
//! use octarine::primitives::paths::filetype::FiletypeBuilder;
//! use octarine::primitives::paths::types::FileCategory;
//!
//! let filetype = FiletypeBuilder::new();
//!
//! // Detect file category
//! assert_eq!(filetype.detect("photo.jpg"), FileCategory::Image);
//! assert_eq!(filetype.detect("main.rs"), FileCategory::SourceCode);
//!
//! // Category checks
//! assert!(filetype.is_image("photo.jpg"));
//! assert!(filetype.is_code("main.rs"));
//! assert!(filetype.is_security_sensitive(".env"));
//! ```
//!
//! ## Using functions directly
//!
//! ```ignore
//! use octarine::primitives::paths::filetype::{detect_file_category, is_image, is_security_sensitive};
//! use octarine::primitives::paths::types::FileCategory;
//!
//! assert_eq!(detect_file_category("photo.jpg"), FileCategory::Image);
//! assert!(is_image("logo.png"));
//! assert!(is_security_sensitive(".env"));
//! ```
//!
//! # Supported File Categories
//!
//! | Category | Extensions | Special Names |
//! |----------|------------|---------------|
//! | Image | jpg, png, gif, svg, webp, etc. | - |
//! | Audio | mp3, wav, flac, ogg, etc. | - |
//! | Video | mp4, mkv, avi, webm, etc. | - |
//! | Document | pdf, doc, docx, odt, etc. | - |
//! | Spreadsheet | xls, xlsx, csv, ods, etc. | - |
//! | Presentation | ppt, pptx, odp, key | - |
//! | Text | txt, md, rst, log | - |
//! | SourceCode | rs, py, js, go, java, etc. | - |
//! | Script | sh, bash, ps1, bat, etc. | - |
//! | Config | json, yaml, toml, ini, etc. | - |
//! | Data | sql, sqlite, parquet, etc. | - |
//! | Archive | zip, tar, rar, 7z, etc. | - |
//! | Compressed | gz, bz2, xz, zst, etc. | - |
//! | Executable | exe, msi, deb, rpm, etc. | - |
//! | Library | dll, so, dylib, a, etc. | - |
//! | Credential | key, pem, p12, etc. | .env, password, secret, api_key |
//! | Certificate | crt, cer, der, etc. | - |
//! | Key | - | id_rsa, id_ed25519, authorized_keys |
//! | Hidden | - | .gitignore, .bashrc, etc. |
//! | Temporary | tmp, temp | backup~, #autosave# |

pub mod builder;
mod detection;

// Re-export builder for convenient access
pub use builder::FiletypeBuilder;

// Re-export detection functions
pub use detection::{
    detect_file_category, find_extension, is_archive, is_audio, is_code, is_config, is_data,
    is_document, is_executable, is_extension_found, is_hidden_or_temp, is_image, is_library,
    is_media, is_security_sensitive, is_text_based, is_video,
};
