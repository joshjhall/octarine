//! Compile-time validation for Config derive.

use darling::Error;

use super::parse::{ConfigOpts, FieldOpts, is_typed_secret};

/// Validate the parsed configuration options.
pub fn validate_config(opts: &ConfigOpts) -> Result<(), Error> {
    let mut errors = Error::accumulator();

    // Struct must not have generics
    if !opts.generics.params.is_empty() {
        errors.push(Error::custom(
            "Config structs cannot have generic parameters",
        ));
    }

    // Validate each field
    for field in opts.fields() {
        errors.handle(validate_field(field));
    }

    errors.finish()
}

/// Validate a single field.
fn validate_field(field: &FieldOpts) -> Result<(), Error> {
    let mut errors = Error::accumulator();

    // Skip fields don't need further validation
    if field.skip {
        if field.default.is_some() {
            errors.push(
                Error::custom("Skipped fields cannot have a default attribute")
                    .with_span(field.name()),
            );
        }
        if field.env.is_some() {
            errors.push(
                Error::custom("Skipped fields cannot have an env attribute")
                    .with_span(field.name()),
            );
        }
        if field.secret {
            errors.push(Error::custom("Skipped fields cannot be secrets").with_span(field.name()));
        }
        if field.typed_secret {
            errors.push(
                Error::custom("Skipped fields cannot be typed secrets").with_span(field.name()),
            );
        }
        if field.flatten {
            errors
                .push(Error::custom("Skipped fields cannot be flattened").with_span(field.name()));
        }
        return errors.finish();
    }

    // typed_secret validation
    if field.typed_secret {
        // Must have TypedSecret<T> type
        if !is_typed_secret(&field.ty) {
            errors.push(
                Error::custom(
                    "typed_secret attribute requires TypedSecret<T> type. \
                     Change the field type to TypedSecret<String> or similar.",
                )
                .with_span(field.name()),
            );
        }

        // Cannot also be marked as regular secret
        if field.secret {
            errors.push(
                Error::custom("Field cannot have both 'secret' and 'typed_secret' attributes")
                    .with_span(field.name()),
            );
        }
    }

    // classification/secret_type only valid with typed_secret
    if field.classification.is_some() && !field.typed_secret {
        errors.push(
            Error::custom("classification attribute requires typed_secret").with_span(field.name()),
        );
    }

    if field.secret_type.is_some() && !field.typed_secret {
        errors.push(
            Error::custom("secret_type attribute requires typed_secret").with_span(field.name()),
        );
    }

    // Validate classification values
    if let Some(ref classification) = field.classification {
        let valid = ["public", "internal", "confidential", "restricted"];
        if !valid.contains(&classification.to_lowercase().as_str()) {
            errors.push(
                Error::custom(format!(
                    "Invalid classification '{}'. Valid values: {}",
                    classification,
                    valid.join(", ")
                ))
                .with_span(field.name()),
            );
        }
    }

    // Validate secret_type values
    if let Some(ref secret_type) = field.secret_type {
        let valid = [
            "apikey",
            "password",
            "authtoken",
            "refreshtoken",
            "encryptionkey",
            "privatekey",
            "keyencryptionkey",
            "masterkey",
            "databasecredential",
            "certificatekey",
            "hmackey",
            "webhooksecret",
            "sshkey",
            "generic",
        ];
        if !valid.contains(&secret_type.to_lowercase().as_str()) {
            errors.push(
                Error::custom(format!(
                    "Invalid secret_type '{}'. Valid values: {}",
                    secret_type,
                    valid.join(", ")
                ))
                .with_span(field.name()),
            );
        }
    }

    // flatten validation
    if field.flatten {
        // Cannot be Option
        if field.is_option_type() {
            errors.push(
                Error::custom("Flattened fields cannot be Option types").with_span(field.name()),
            );
        }

        // Cannot be a secret
        if field.secret || field.typed_secret {
            errors
                .push(Error::custom("Flattened fields cannot be secrets").with_span(field.name()));
        }

        // Cannot have default
        if field.default.is_some() {
            errors.push(
                Error::custom("Flattened fields cannot have default values")
                    .with_span(field.name()),
            );
        }

        // Cannot have custom env
        if field.env.is_some() {
            errors.push(
                Error::custom("Flattened fields cannot have custom env names")
                    .with_span(field.name()),
            );
        }
    }

    errors.finish()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use darling::FromDeriveInput;
    use syn::parse_quote;

    use super::*;

    fn parse_config(input: syn::DeriveInput) -> Result<ConfigOpts, darling::Error> {
        ConfigOpts::from_derive_input(&input)
    }

    #[test]
    fn test_valid_simple_config() {
        let input: syn::DeriveInput = parse_quote! {
            #[config(prefix = "APP")]
            struct AppConfig {
                port: u16,
                host: String,
            }
        };

        let opts = parse_config(input).unwrap();
        assert!(validate_config(&opts).is_ok());
    }

    #[test]
    fn test_rejects_generic_struct() {
        let input: syn::DeriveInput = parse_quote! {
            struct Config<T> {
                value: T,
            }
        };

        let opts = parse_config(input).unwrap();
        let result = validate_config(&opts);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("generic"));
    }

    #[test]
    fn test_skip_with_other_attrs() {
        let input: syn::DeriveInput = parse_quote! {
            struct Config {
                #[config(skip, default = "foo")]
                field: String,
            }
        };

        let opts = parse_config(input).unwrap();
        let result = validate_config(&opts);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Skipped"));
    }

    #[test]
    fn test_typed_secret_requires_type() {
        let input: syn::DeriveInput = parse_quote! {
            struct Config {
                #[config(typed_secret)]
                api_key: String,  // Wrong type!
            }
        };

        let opts = parse_config(input).unwrap();
        let result = validate_config(&opts);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("TypedSecret<T>"));
    }

    #[test]
    fn test_classification_requires_typed_secret() {
        let input: syn::DeriveInput = parse_quote! {
            struct Config {
                #[config(classification = "confidential")]
                api_key: String,
            }
        };

        let opts = parse_config(input).unwrap();
        let result = validate_config(&opts);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("requires typed_secret")
        );
    }

    #[test]
    fn test_invalid_classification() {
        let input: syn::DeriveInput = parse_quote! {
            struct Config {
                #[config(typed_secret, classification = "super_secret")]
                api_key: TypedSecret<String>,
            }
        };

        let opts = parse_config(input).unwrap();
        let result = validate_config(&opts);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid classification")
        );
    }

    #[test]
    fn test_flatten_cannot_be_option() {
        let input: syn::DeriveInput = parse_quote! {
            struct Config {
                #[config(flatten)]
                database: Option<DatabaseConfig>,
            }
        };

        let opts = parse_config(input).unwrap();
        let result = validate_config(&opts);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Option"));
    }
}
