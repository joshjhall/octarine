//! JSON security detection and validation
//!
//! Detects depth bombs and size limit violations.

mod detection;
mod validation;

pub(crate) use detection::{detect_json_threats, exceeds_depth, exceeds_size};
pub(crate) use validation::validate_json_safe;
