//! LDAP injection detection and prevention
//!
//! Provides pattern-based detection and escaping for LDAP injection (CWE-90).
//!
//! # Threat Categories
//!
//! | Threat | Description | Example |
//! |--------|-------------|---------|
//! | Filter injection | Breaking out of filters | `admin)(` |
//! | Wildcard enumeration | Using * for enumeration | `*` |
//! | Null byte injection | Truncating filters | `\x00` |
//!
//! # Note
//!
//! This module will be fully implemented in Phase 3.

pub(super) mod detection;
pub(super) mod patterns;
pub(super) mod sanitization;
pub(super) mod validation;

// Internal re-exports for use by the builder
pub(super) use detection::{detect_ldap_threats, is_ldap_injection_present};
pub(super) use sanitization::{escape_ldap_dn, escape_ldap_filter};
pub(super) use validation::{
    validate_ldap_attribute_name, validate_ldap_dn_component, validate_ldap_filter,
};
