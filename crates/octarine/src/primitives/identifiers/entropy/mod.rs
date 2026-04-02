//! Entropy analysis primitives
//!
//! Shannon entropy, character diversity, charset classification, and
//! high-entropy string detection used for finding potential secrets,
//! API keys, and generated passwords in text.

pub mod charsets;
mod core;
mod detection;
mod types;

pub use self::charsets::{CharsetClass, classify_charset, is_base64_charset, is_hex_charset};
pub use self::core::{calculate_char_diversity, calculate_shannon_entropy};
pub use self::detection::{
    detect_high_entropy_strings_in_text, detect_high_entropy_strings_with_config, is_high_entropy,
    is_high_entropy_base64, is_high_entropy_hex,
};
pub use self::types::EntropyConfig;
