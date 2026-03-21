//! YAML security detection and validation
//!
//! Detects unsafe tags and anchor/alias bombs.

mod detection;
mod validation;

pub(crate) use detection::{detect_yaml_threats, has_anchor_bomb, has_unsafe_tag, is_yaml_unsafe};
pub(crate) use validation::validate_yaml_safe;
