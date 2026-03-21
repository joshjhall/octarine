//! YAML serialization primitives
//!
//! Pure YAML serialization operations.

use serde::Serialize;

use crate::primitives::types::{Problem, Result};

/// Serialize a value to YAML string
pub(crate) fn serialize_yaml<T: Serialize>(value: &T) -> Result<String> {
    serde_yaml::to_string(value).map_err(|e| Problem::Parse(e.to_string()))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use serde_yaml::Value;

    #[test]
    fn test_serialize_yaml_mapping() {
        let mut mapping = serde_yaml::Mapping::new();
        mapping.insert(Value::String("key".into()), Value::String("value".into()));
        let value = Value::Mapping(mapping);

        let result = serialize_yaml(&value);
        assert!(result.is_ok());

        let yaml = result.expect("valid");
        assert!(yaml.contains("key:"));
        assert!(yaml.contains("value"));
    }

    #[test]
    fn test_serialize_yaml_sequence() {
        let sequence = vec![Value::String("item1".into()), Value::String("item2".into())];
        let value = Value::Sequence(sequence);

        let result = serialize_yaml(&value);
        assert!(result.is_ok());

        let yaml = result.expect("valid");
        assert!(yaml.contains("- item1"));
        assert!(yaml.contains("- item2"));
    }

    #[test]
    fn test_serialize_yaml_nested() {
        let mut inner = serde_yaml::Mapping::new();
        inner.insert(Value::String("child".into()), Value::String("value".into()));

        let mut outer = serde_yaml::Mapping::new();
        outer.insert(Value::String("parent".into()), Value::Mapping(inner));

        let value = Value::Mapping(outer);
        let result = serialize_yaml(&value);
        assert!(result.is_ok());

        let yaml = result.expect("valid");
        assert!(yaml.contains("parent:"));
        assert!(yaml.contains("child:"));
    }

    #[test]
    fn test_serialize_yaml_scalars() {
        let mut mapping = serde_yaml::Mapping::new();
        mapping.insert(
            Value::String("string".into()),
            Value::String("hello".into()),
        );
        mapping.insert(Value::String("number".into()), Value::Number(42.into()));
        mapping.insert(Value::String("boolean".into()), Value::Bool(true));
        mapping.insert(Value::String("null".into()), Value::Null);

        let value = Value::Mapping(mapping);
        let result = serialize_yaml(&value);
        assert!(result.is_ok());
    }
}
