//! Attribute parsing using darling.

use darling::{FromDeriveInput, FromField};
use syn::{Generics, Ident, Type, Visibility};

/// Struct-level configuration options.
#[derive(Debug, FromDeriveInput)]
#[darling(attributes(config), supports(struct_named))]
pub struct ConfigOpts {
    /// The struct identifier.
    pub ident: Ident,

    /// The struct visibility.
    pub vis: Visibility,

    /// The struct generics (must be empty for Config).
    pub generics: Generics,

    /// Struct fields.
    pub data: darling::ast::Data<(), FieldOpts>,

    /// Environment variable prefix (e.g., "APP" -> "APP_PORT").
    #[darling(default)]
    pub prefix: Option<String>,

    /// Separator between prefix and field name (default: "_").
    #[darling(default = "default_separator")]
    pub separator: String,

    /// Config file path (optional).
    #[darling(default)]
    pub file: Option<String>,
}

fn default_separator() -> String {
    "_".to_string()
}

/// Field-level configuration options.
#[derive(Debug, FromField)]
#[darling(attributes(config))]
pub struct FieldOpts {
    /// Field identifier.
    pub ident: Option<Ident>,

    /// Field type.
    pub ty: Type,

    /// Field visibility.
    #[allow(dead_code)]
    pub vis: Visibility,

    /// Default value as string literal.
    #[darling(default)]
    pub default: Option<String>,

    /// Custom environment variable name (overrides auto-generated).
    #[darling(default)]
    pub env: Option<String>,

    /// Mark as secret (masked in logs).
    #[darling(default)]
    pub secret: bool,

    /// Use TypedSecret wrapper.
    #[darling(default)]
    pub typed_secret: bool,

    /// Classification for typed secrets.
    #[darling(default)]
    pub classification: Option<String>,

    /// Secret type for typed secrets.
    #[darling(default)]
    pub secret_type: Option<String>,

    /// Flatten nested struct.
    #[darling(default)]
    pub flatten: bool,

    /// Nested prefix for flattened structs.
    #[darling(default)]
    pub nested_prefix: Option<String>,

    /// Skip this field entirely.
    #[darling(default)]
    pub skip: bool,

    /// Rename the field for env var lookup.
    #[darling(default)]
    pub rename: Option<String>,
}

impl ConfigOpts {
    /// Get the struct fields as a Vec.
    ///
    /// # Panics
    ///
    /// Panics if the data is not a struct (produces a compile error).
    #[allow(clippy::panic)]
    pub fn fields(&self) -> Vec<&FieldOpts> {
        match &self.data {
            darling::ast::Data::Struct(fields) => fields.iter().collect(),
            _ => panic!("Config only supports structs"),
        }
    }
}

impl FieldOpts {
    /// Get the field name.
    ///
    /// # Panics
    ///
    /// Panics if the field is unnamed (produces a compile error).
    #[allow(clippy::expect_used)]
    pub fn name(&self) -> &Ident {
        self.ident.as_ref().expect("Config requires named fields")
    }

    /// Check if the type is `Option<T>`.
    pub fn is_option_type(&self) -> bool {
        is_option(&self.ty)
    }
}

/// Check if a type is `Option<T>`.
fn is_option(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
    {
        return segment.ident == "Option";
    }
    false
}

/// Check if a type is `TypedSecret<T>`.
pub fn is_typed_secret(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
    {
        return segment.ident == "TypedSecret";
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn test_is_option() {
        let ty: Type = parse_quote!(Option<String>);
        assert!(is_option(&ty));

        let ty: Type = parse_quote!(String);
        assert!(!is_option(&ty));

        let ty: Type = parse_quote!(std::option::Option<i32>);
        assert!(is_option(&ty));
    }

    #[test]
    fn test_is_typed_secret() {
        let ty: Type = parse_quote!(TypedSecret<String>);
        assert!(is_typed_secret(&ty));

        let ty: Type = parse_quote!(String);
        assert!(!is_typed_secret(&ty));
    }
}
