//! Common utilities for identifier detection, validation, and sanitization
//!
//! This module provides shared primitives used across all identifier domains:
//!
//! - `patterns` - Compiled regex patterns for text scanning
//! - `luhn` - Luhn algorithm for credit card validation
//! - `masking` - Masking and redaction strategies
//! - `utils` - Common validation utilities
//!
//! ## Design Principles
//!
//! 1. **No Logging**: Pure functions, no trace/debug calls
//! 2. **No Dependencies**: Only external crates (regex, etc.)
//! 3. **Reusable**: Used by all domain modules

pub(crate) mod luhn;
pub(crate) mod masking;
pub(crate) mod patterns;
pub(crate) mod utils;

// Re-export commonly used utilities for sibling modules
pub use luhn::{
    is_valid as is_luhn_valid, is_valid_with_min_length as is_luhn_valid_with_min_length,
};
pub use masking::{
    alphanumeric_only, create_mask, digits_only, mask_all, mask_digits_preserve_format,
    mask_middle, show_first_and_last, show_first_n, show_last_n,
};
pub use utils::{
    is_control_chars_present, is_identifier_chars, is_injection_pattern_present,
    is_severe_injection_pattern_present, is_sql_injection_pattern_present, is_valid_start_char,
};
