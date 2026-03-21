//! YAML parsing and serialization primitives
//!
//! Pure YAML operations with no security checks or file I/O.
//! For safe parsing with unsafe tag prevention, use `security::formats` or `runtime::formats`.

mod parsing;
mod serialization;

pub(crate) use parsing::{parse_yaml, parse_yaml_with_options};
pub(crate) use serialization::serialize_yaml;
