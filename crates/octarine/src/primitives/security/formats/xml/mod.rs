//! XML security detection and validation
//!
//! Detects XXE attacks, DTD declarations, and entity expansion threats.

mod detection;
mod validation;

pub(crate) use detection::{
    detect_xml_threats, has_dtd_declaration, has_external_entity, has_parameter_entity,
    is_xxe_present,
};
pub(crate) use validation::validate_xml_safe;
