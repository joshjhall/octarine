//! JSON parsing and serialization primitives
//!
//! Pure JSON operations with no security checks or file I/O.

mod parsing;
mod serialization;

pub(crate) use parsing::{parse_json, parse_json_with_options};
pub(crate) use serialization::{serialize_json, serialize_json_pretty};
