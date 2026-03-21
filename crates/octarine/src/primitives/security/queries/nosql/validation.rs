//! NoSQL value validation
//!
//! Validation functions for NoSQL values to prevent injection.
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::security::queries::nosql::validation;
//!
//! // Validate user input before using in NoSQL query
//! validation::validate_nosql_value(user_input)?;
//!
//! // Validate a field name
//! validation::validate_nosql_field_name(field_name)?;
//! ```

use super::detection;
use crate::primitives::types::Problem;

/// Maximum allowed length for NoSQL field names
const MAX_FIELD_NAME_LENGTH: usize = 128;

/// Validate that a NoSQL value is safe for use in queries
///
/// Checks for injection patterns including operators, JavaScript,
/// prototype pollution, and array injection.
///
/// # Arguments
///
/// * `value` - The value to validate
///
/// # Returns
///
/// `Ok(())` if the value is safe, `Err(Problem)` if injection detected
pub fn validate_nosql_value(value: &str) -> Result<(), Problem> {
    if detection::is_nosql_injection_present(value) {
        let threats = detection::detect_nosql_threats(value);
        let threat_desc = threats
            .iter()
            .map(|t| t.description())
            .collect::<Vec<_>>()
            .join(", ");

        return Err(Problem::validation(format!(
            "NoSQL injection detected: {threat_desc}"
        )));
    }

    Ok(())
}

/// Validate that a field name is safe for NoSQL operations
///
/// Field names must not start with $ or contain special characters.
///
/// # Arguments
///
/// * `field_name` - The field name to validate
///
/// # Returns
///
/// `Ok(())` if the field name is safe, `Err(Problem)` otherwise
pub fn validate_nosql_field_name(field_name: &str) -> Result<(), Problem> {
    if field_name.is_empty() {
        return Err(Problem::validation("Field name cannot be empty"));
    }

    if field_name.len() > MAX_FIELD_NAME_LENGTH {
        return Err(Problem::validation(format!(
            "Field name exceeds maximum length of {MAX_FIELD_NAME_LENGTH} characters"
        )));
    }

    // Field names cannot start with $
    if field_name.starts_with('$') {
        return Err(Problem::validation(
            "Field name cannot start with '$' (reserved for operators)",
        ));
    }

    // Check for null bytes
    if field_name.contains('\0') {
        return Err(Problem::validation("Field name cannot contain null bytes"));
    }

    // Check for prototype pollution keys
    let lower = field_name.to_lowercase();
    if lower == "__proto__" || lower == "constructor" || lower == "prototype" {
        return Err(Problem::validation(format!(
            "Field name '{field_name}' is a prototype pollution risk"
        )));
    }

    Ok(())
}

/// Validate that a collection name is safe for NoSQL operations
///
/// # Arguments
///
/// * `collection` - The collection name to validate
///
/// # Returns
///
/// `Ok(())` if the collection name is safe, `Err(Problem)` otherwise
pub fn validate_nosql_collection(collection: &str) -> Result<(), Problem> {
    if collection.is_empty() {
        return Err(Problem::validation("Collection name cannot be empty"));
    }

    if collection.len() > MAX_FIELD_NAME_LENGTH {
        return Err(Problem::validation(format!(
            "Collection name exceeds maximum length of {MAX_FIELD_NAME_LENGTH} characters"
        )));
    }

    // Collection names cannot start with $ or contain null bytes
    if collection.starts_with('$') {
        return Err(Problem::validation("Collection name cannot start with '$'"));
    }

    if collection.contains('\0') {
        return Err(Problem::validation(
            "Collection name cannot contain null bytes",
        ));
    }

    // System collections start with "system."
    if collection.starts_with("system.") {
        return Err(Problem::validation("Cannot use system collection names"));
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_nosql_value_safe() {
        assert!(validate_nosql_value("hello").is_ok());
        assert!(validate_nosql_value("user@example.com").is_ok());
        assert!(validate_nosql_value("John Doe").is_ok());
        assert!(validate_nosql_value("123").is_ok());
    }

    #[test]
    fn test_validate_nosql_value_operators() {
        assert!(validate_nosql_value(r#"{ "$gt": "" }"#).is_err());
        assert!(validate_nosql_value("$where").is_err());
        assert!(validate_nosql_value(r#"{"$ne": null}"#).is_err());
    }

    #[test]
    fn test_validate_nosql_value_prototype() {
        assert!(validate_nosql_value("__proto__").is_err());
        assert!(validate_nosql_value("constructor.prototype").is_err());
    }

    #[test]
    fn test_validate_nosql_field_name_safe() {
        assert!(validate_nosql_field_name("username").is_ok());
        assert!(validate_nosql_field_name("user_name").is_ok());
        assert!(validate_nosql_field_name("field123").is_ok());
    }

    #[test]
    fn test_validate_nosql_field_name_invalid() {
        assert!(validate_nosql_field_name("").is_err());
        assert!(validate_nosql_field_name("$gt").is_err());
        assert!(validate_nosql_field_name("__proto__").is_err());
        assert!(validate_nosql_field_name("constructor").is_err());
    }

    #[test]
    fn test_validate_nosql_collection_safe() {
        assert!(validate_nosql_collection("users").is_ok());
        assert!(validate_nosql_collection("my_collection").is_ok());
    }

    #[test]
    fn test_validate_nosql_collection_invalid() {
        assert!(validate_nosql_collection("").is_err());
        assert!(validate_nosql_collection("$cmd").is_err());
        assert!(validate_nosql_collection("system.users").is_err());
    }
}
