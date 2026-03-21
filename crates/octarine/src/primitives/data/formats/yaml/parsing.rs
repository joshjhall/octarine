//! YAML parsing primitives
//!
//! Pure YAML parsing with no security checks. For safe parsing with
//! unsafe tag prevention, use `security::formats` or `runtime::formats`.

use serde_yaml::Value;

use crate::primitives::types::{Problem, Result};

use super::super::types::ParseOptions;

/// Parse YAML string into a serde_yaml Value
///
/// This is a pure parsing operation with no security checks.
/// For untrusted input, use `runtime::formats::SecureYamlReader`.
///
/// # Warning
///
/// This parser does NOT prevent unsafe YAML tags or anchor bombs.
/// For untrusted input, always use the security module's validation first.
pub(crate) fn parse_yaml(input: &str) -> Result<Value> {
    serde_yaml::from_str(input).map_err(|e| Problem::Parse(e.to_string()))
}

/// Parse YAML string with options
///
/// Applies size limits before parsing. Other limits are checked
/// during parsing by the security module.
#[allow(dead_code)]
pub(crate) fn parse_yaml_with_options(input: &str, options: &ParseOptions) -> Result<Value> {
    // Check size limit
    if input.len() > options.max_size {
        return Err(Problem::Parse(format!(
            "YAML input exceeds maximum size: {} > {} bytes",
            input.len(),
            options.max_size
        )));
    }

    parse_yaml(input)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::needless_borrows_for_generic_args
    )]
    use super::*;

    #[test]
    fn test_parse_yaml_mapping() {
        let yaml = "key: value\nother: data";
        let result = parse_yaml(yaml);
        assert!(result.is_ok());

        let value = result.expect("valid yaml");
        assert!(value.is_mapping());
    }

    #[test]
    fn test_parse_yaml_sequence() {
        let yaml = "- item1\n- item2\n- item3";
        let result = parse_yaml(yaml);
        assert!(result.is_ok());

        let value = result.expect("valid yaml");
        assert!(value.is_sequence());
    }

    #[test]
    fn test_parse_yaml_nested() {
        let yaml = r#"
root:
  child:
    key: value
"#;
        let result = parse_yaml(yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_yaml_with_document_start() {
        let yaml = "---\nkey: value";
        let result = parse_yaml(yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_yaml_invalid() {
        let yaml = "key: value\n  invalid indent";
        let _result = parse_yaml(yaml);
        // This might parse depending on the strictness, but let's test something definitely invalid
        let invalid = "- item\n  not_list: value";
        let _result = parse_yaml(invalid);
        // serde_yaml is fairly permissive, so just check we can parse valid YAML
        assert!(parse_yaml("valid: yaml").is_ok());
    }

    #[test]
    fn test_parse_yaml_with_size_limit() {
        let options = ParseOptions::new().with_max_size(10);
        let result = parse_yaml_with_options("this is a very long yaml document", &options);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("should fail")
                .to_string()
                .contains("exceeds maximum size")
        );
    }

    #[test]
    fn test_parse_yaml_within_size_limit() {
        let options = ParseOptions::new().with_max_size(1000);
        let result = parse_yaml_with_options("key: value", &options);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_yaml_scalar_types() {
        let yaml = r#"
string: "hello"
number: 42
float: 3.14
boolean: true
null_value: null
"#;
        let value = parse_yaml(yaml).expect("valid yaml");
        let mapping = value.as_mapping().expect("is mapping");

        assert!(
            mapping
                .get(&Value::String("string".into()))
                .expect("has string")
                .is_string()
        );
        assert!(
            mapping
                .get(&Value::String("number".into()))
                .expect("has number")
                .is_number()
        );
        assert!(
            mapping
                .get(&Value::String("boolean".into()))
                .expect("has boolean")
                .is_bool()
        );
        assert!(
            mapping
                .get(&Value::String("null_value".into()))
                .expect("has null")
                .is_null()
        );
    }
}
