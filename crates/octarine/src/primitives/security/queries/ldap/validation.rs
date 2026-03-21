//! LDAP filter validation
//!
//! Validation functions for LDAP filters to prevent injection.
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::security::queries::ldap::validation;
//!
//! // Validate user input for LDAP filter
//! validation::validate_ldap_filter(user_input)?;
//!
//! // Validate a DN component
//! validation::validate_ldap_dn_component(dn_value)?;
//! ```

use super::detection;
use crate::primitives::types::Problem;

/// Maximum allowed length for LDAP attribute values
const MAX_ATTRIBUTE_VALUE_LENGTH: usize = 1024;

/// Maximum allowed length for DN components
const MAX_DN_COMPONENT_LENGTH: usize = 256;

/// Validate that an LDAP filter value is safe
///
/// Checks for injection patterns that could modify filter logic.
///
/// # Arguments
///
/// * `filter` - The filter value to validate
///
/// # Returns
///
/// `Ok(())` if the filter value is safe, `Err(Problem)` if injection detected
pub fn validate_ldap_filter(filter: &str) -> Result<(), Problem> {
    if filter.is_empty() {
        return Ok(());
    }

    if filter.len() > MAX_ATTRIBUTE_VALUE_LENGTH {
        return Err(Problem::validation(format!(
            "LDAP filter value exceeds maximum length of {MAX_ATTRIBUTE_VALUE_LENGTH} characters"
        )));
    }

    if detection::is_ldap_injection_present(filter) {
        let threats = detection::detect_ldap_threats(filter);
        let threat_desc = threats
            .iter()
            .map(|t| t.description())
            .collect::<Vec<_>>()
            .join(", ");

        return Err(Problem::validation(format!(
            "LDAP injection detected: {threat_desc}"
        )));
    }

    Ok(())
}

/// Validate that an LDAP DN component is safe
///
/// Checks for special characters that could modify DN parsing.
///
/// # Arguments
///
/// * `value` - The DN component value to validate
///
/// # Returns
///
/// `Ok(())` if the value is safe, `Err(Problem)` if special characters detected
pub fn validate_ldap_dn_component(value: &str) -> Result<(), Problem> {
    if value.is_empty() {
        return Err(Problem::validation("DN component cannot be empty"));
    }

    if value.len() > MAX_DN_COMPONENT_LENGTH {
        return Err(Problem::validation(format!(
            "DN component exceeds maximum length of {MAX_DN_COMPONENT_LENGTH} characters"
        )));
    }

    // Check for null bytes
    if value.contains('\0') {
        return Err(Problem::validation(
            "DN component cannot contain null bytes",
        ));
    }

    // Check for unescaped special characters
    for c in value.chars() {
        match c {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=' => {
                return Err(Problem::validation(format!(
                    "DN component contains unescaped special character: '{c}'"
                )));
            }
            _ => {}
        }
    }

    Ok(())
}

/// Validate that an LDAP attribute name is safe
///
/// Attribute names must be alphanumeric with hyphens allowed.
///
/// # Arguments
///
/// * `name` - The attribute name to validate
///
/// # Returns
///
/// `Ok(())` if the name is valid, `Err(Problem)` otherwise
pub fn validate_ldap_attribute_name(name: &str) -> Result<(), Problem> {
    if name.is_empty() {
        return Err(Problem::validation("Attribute name cannot be empty"));
    }

    if name.len() > 128 {
        return Err(Problem::validation(
            "Attribute name exceeds maximum length of 128 characters",
        ));
    }

    // First character must be alphabetic
    if let Some(c) = name.chars().next()
        && !c.is_ascii_alphabetic()
    {
        return Err(Problem::validation(
            "Attribute name must start with a letter",
        ));
    }

    // Rest must be alphanumeric or hyphen
    for c in name.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' {
            return Err(Problem::validation(format!(
                "Attribute name contains invalid character: '{c}'"
            )));
        }
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
    fn test_validate_ldap_filter_safe() {
        assert!(validate_ldap_filter("admin").is_ok());
        assert!(validate_ldap_filter("john.doe").is_ok());
        assert!(validate_ldap_filter("user@example.com").is_ok());
        assert!(validate_ldap_filter("").is_ok());
    }

    #[test]
    fn test_validate_ldap_filter_injection() {
        assert!(validate_ldap_filter("admin)(").is_err());
        assert!(validate_ldap_filter("test*").is_err());
        assert!(validate_ldap_filter("user|admin").is_err());
        assert!(validate_ldap_filter("admin\0").is_err());
    }

    #[test]
    fn test_validate_ldap_dn_component_safe() {
        assert!(validate_ldap_dn_component("admin").is_ok());
        assert!(validate_ldap_dn_component("John Doe").is_ok());
        assert!(validate_ldap_dn_component("user123").is_ok());
    }

    #[test]
    fn test_validate_ldap_dn_component_invalid() {
        assert!(validate_ldap_dn_component("").is_err());
        assert!(validate_ldap_dn_component("user,name").is_err());
        assert!(validate_ldap_dn_component("test=value").is_err());
        assert!(validate_ldap_dn_component("user\0").is_err());
    }

    #[test]
    fn test_validate_ldap_attribute_name_safe() {
        assert!(validate_ldap_attribute_name("cn").is_ok());
        assert!(validate_ldap_attribute_name("uid").is_ok());
        assert!(validate_ldap_attribute_name("objectClass").is_ok());
        assert!(validate_ldap_attribute_name("member-of").is_ok());
    }

    #[test]
    fn test_validate_ldap_attribute_name_invalid() {
        assert!(validate_ldap_attribute_name("").is_err());
        assert!(validate_ldap_attribute_name("1attr").is_err());
        assert!(validate_ldap_attribute_name("attr=value").is_err());
        assert!(validate_ldap_attribute_name("attr(test)").is_err());
    }
}
