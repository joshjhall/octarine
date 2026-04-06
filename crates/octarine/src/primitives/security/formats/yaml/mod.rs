//! YAML security detection and validation
//!
//! Detects unsafe tags and anchor/alias bombs.

mod detection;
mod validation;

pub(crate) use detection::{
    detect_yaml_threats, is_anchor_bomb_present, is_unsafe_tag_present, is_yaml_unsafe,
};
pub(crate) use validation::validate_yaml_safe;
