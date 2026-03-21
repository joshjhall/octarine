//! Builder pattern for personal identifier operations
//!
//! Provides a clean interface to detection, validation, sanitization,
//! and conversion functions for personal identifiers.
//!
//! ## Module Organization
//!
//! - [`core`] - PersonalIdentifierBuilder struct and constructor
//! - [`detection_methods`] - Detection methods (is_email, find_emails_in_text, etc.)
//! - [`validation_methods`] - Validation methods (validate_email, validate_phone, etc.)
//! - [`sanitization_methods`] - Sanitization and redaction methods
//! - [`conversion_methods`] - Format conversion methods
//! - [`cache_methods`] - Cache statistics and management
//! - [`test_pattern_methods`] - Test pattern detection

mod cache_methods;
mod conversion_methods;
mod core;
mod detection_methods;
mod sanitization_methods;
mod test_pattern_methods;
mod validation_methods;

pub use self::core::{PersonalIdentifierBuilder, PhoneFormatStyle};
