//! NoSQL injection detection and prevention
//!
//! Provides pattern-based detection for NoSQL injection attacks (CWE-943).
//!
//! # Threat Categories
//!
//! | Threat | Description | Example |
//! |--------|-------------|---------|
//! | Operator injection | MongoDB operators | `{ "$gt": "" }` |
//! | JavaScript injection | $where clause abuse | `{ "$where": "sleep(5)" }` |
//! | Prototype pollution | Prototype chain manipulation | `{ "__proto__": {} }` |
//!
//! # Example
//!
//! ```ignore
//! // Use the public API via security/queries module:
//! use octarine::security::queries::{
//!     is_nosql_injection_present,
//!     validate_nosql_value,
//!     sanitize_nosql_value,
//! };
//!
//! // Detection (returns bool)
//! assert!(is_nosql_injection_present(r#"{ "$gt": "" }"#));
//!
//! // Validation (returns Result)
//! assert!(validate_nosql_value("hello").is_ok());
//! assert!(validate_nosql_value("$gt").is_err());
//!
//! // Sanitization (returns clean string)
//! assert_eq!(sanitize_nosql_value("$gt"), "gt");
//! ```

pub(super) mod detection;
pub(super) mod patterns;
pub(super) mod sanitization;
pub(super) mod validation;

// Internal re-exports for use by the builder
pub(super) use detection::{detect_nosql_threats, is_nosql_injection_present};
pub(super) use sanitization::{
    escape_nosql_field, escape_nosql_path, sanitize_nosql_value, strip_nosql_operators,
    strip_prototype_patterns,
};
pub(super) use validation::{
    validate_nosql_collection, validate_nosql_field_name, validate_nosql_value,
};
