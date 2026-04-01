//! Entropy analysis primitives
//!
//! Shannon entropy and character diversity calculations used for
//! detecting high-entropy strings (potential secrets, API keys, etc.).

mod core;

pub use self::core::{calculate_char_diversity, calculate_shannon_entropy};
