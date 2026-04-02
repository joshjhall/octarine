//! Entropy analysis primitives
//!
//! Shannon entropy, character diversity, and charset classification
//! used for detecting high-entropy strings (potential secrets, API keys, etc.).

mod charsets;
mod core;

pub use self::charsets::{CharsetClass, classify_charset, is_base64_charset, is_hex_charset};
pub use self::core::{calculate_char_diversity, calculate_shannon_entropy};
