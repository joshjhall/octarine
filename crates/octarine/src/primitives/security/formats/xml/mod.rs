//! XML security detection and validation
//!
//! Detects XXE attacks, DTD declarations, and entity expansion threats.

mod detection;
mod validation;

pub(crate) use detection::{
    detect_xml_threats, is_dtd_declaration_present, is_external_entity_present,
    is_parameter_entity_present, is_xxe_present,
};
pub(crate) use validation::validate_xml_safe;
