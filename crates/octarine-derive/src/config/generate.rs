//! Code generation for Config derive.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::parse::{ConfigOpts, FieldOpts};

/// Generate the impl block for the Config derive.
pub fn generate_impl(opts: &ConfigOpts) -> TokenStream {
    let struct_name = &opts.ident;
    let vis = &opts.vis;
    let prefix = opts.prefix.as_deref();
    let separator = &opts.separator;
    let file = &opts.file;

    // Generate field loading for load()
    let field_loaders = generate_field_loaders(opts, prefix, separator);

    // Generate field loading for load_with_prefix()
    let field_loaders_with_prefix = generate_field_loaders_with_prefix(opts, separator);

    // Get field names for struct construction
    let field_names: Vec<_> = opts.fields().iter().map(|f| f.name()).collect();

    // Generate file loading code
    let file_loading = match file {
        Some(path) => quote! {
            let builder = builder.with_optional_file(::std::path::Path::new(#path));
        },
        None => quote! {},
    };

    // Generate prefix setup for load()
    let prefix_setup = match prefix {
        Some(p) => quote! {
            let builder = ::octarine::runtime::config::ConfigBuilder::new()
                .with_prefix(#p)
                .with_separator(#separator);
        },
        None => quote! {
            let builder = ::octarine::runtime::config::ConfigBuilder::new()
                .with_separator(#separator);
        },
    };

    quote! {
        impl #struct_name {
            /// Load configuration from environment variables and optional config file.
            ///
            /// Priority (highest to lowest):
            /// 1. Environment variables
            /// 2. Config file (if specified)
            /// 3. Default values
            #vis fn load() -> ::std::result::Result<Self, ::octarine::runtime::config::ConfigError> {
                #prefix_setup
                #file_loading
                #field_loaders

                Ok(Self {
                    #(#field_names,)*
                })
            }

            /// Load configuration with a custom prefix.
            ///
            /// This is used for nested/flattened configuration structs.
            #vis fn load_with_prefix(
                prefix: &str,
            ) -> ::std::result::Result<Self, ::octarine::runtime::config::ConfigError> {
                let builder = ::octarine::runtime::config::ConfigBuilder::new()
                    .with_prefix(prefix)
                    .with_separator(#separator);

                #field_loaders_with_prefix

                Ok(Self {
                    #(#field_names,)*
                })
            }
        }
    }
}

/// Generate field loading statements for load().
fn generate_field_loaders(opts: &ConfigOpts, prefix: Option<&str>, separator: &str) -> TokenStream {
    let loaders: Vec<TokenStream> = opts
        .fields()
        .iter()
        .map(|field| generate_field_loader(field, prefix, separator))
        .collect();

    quote! {
        #(#loaders)*
    }
}

/// Generate field loading statements for load_with_prefix().
fn generate_field_loaders_with_prefix(opts: &ConfigOpts, separator: &str) -> TokenStream {
    let loaders: Vec<TokenStream> = opts
        .fields()
        .iter()
        .map(|field| generate_field_loader_with_dynamic_prefix(field, separator))
        .collect();

    quote! {
        #(#loaders)*
    }
}

/// Generate loading code for a single field (static prefix).
///
/// When the builder has `with_prefix()` set, we pass just the field name
/// (without prefix) and let the builder add the prefix. Exception: fields
/// with custom `env` attribute use that name directly.
fn generate_field_loader(field: &FieldOpts, prefix: Option<&str>, separator: &str) -> TokenStream {
    let ident = field.name();

    // Skip fields
    if field.skip {
        return quote! {
            let #ident = ::std::default::Default::default();
        };
    }

    // Flatten fields - compute full nested prefix
    if field.flatten {
        let ty = &field.ty;
        let nested_prefix = field
            .nested_prefix
            .clone()
            .unwrap_or_else(|| ident.to_string())
            .to_uppercase();

        return match prefix {
            Some(p) => {
                let full_prefix = format!("{}{}{}", p, separator, nested_prefix);
                quote! {
                    let #ident = <#ty>::load_with_prefix(#full_prefix)?;
                }
            }
            None => {
                quote! {
                    let #ident = <#ty>::load_with_prefix(#nested_prefix)?;
                }
            }
        };
    }

    // For custom env names, use them directly (no prefix added by builder)
    // For regular fields, just pass the field name in uppercase
    let env_name = if let Some(ref custom_env) = field.env {
        // Custom env: use as-is, but we need to NOT use with_prefix for this field
        // Actually, since we're using with_prefix on the builder, we need to
        // pass the full custom name and rely on the double-prefix protection
        custom_env.clone()
    } else {
        // Regular field: just the uppercase field name, builder adds prefix
        field
            .rename
            .as_ref()
            .map(|r| r.to_uppercase())
            .unwrap_or_else(|| ident.to_string().to_uppercase())
    };

    // TypedSecret fields
    if field.typed_secret {
        let classification = classification_tokens(field.classification.as_deref());
        let secret_type = secret_type_tokens(field.secret_type.as_deref());

        return quote! {
            let #ident = builder.get_typed_secret(
                #env_name,
                #secret_type,
                #classification,
            )?;
        };
    }

    // Secret fields
    if field.secret {
        return generate_secret_field(field, &env_name);
    }

    // Regular fields
    generate_regular_field(field, &env_name)
}

/// Generate loading code for a single field (dynamic prefix).
///
/// Similar to static prefix version - pass just field names to the builder
/// since it has `with_prefix()` set.
fn generate_field_loader_with_dynamic_prefix(field: &FieldOpts, separator: &str) -> TokenStream {
    let ident = field.name();

    // Skip fields
    if field.skip {
        return quote! {
            let #ident = ::std::default::Default::default();
        };
    }

    // Flatten fields - compute full nested prefix for recursive call
    if field.flatten {
        let ty = &field.ty;
        let nested_prefix = field
            .nested_prefix
            .as_deref()
            .map(|s| s.to_uppercase())
            .unwrap_or_else(|| ident.to_string().to_uppercase());

        return quote! {
            let nested_prefix = format!("{}{}{}", prefix, #separator, #nested_prefix);
            let #ident = <#ty>::load_with_prefix(&nested_prefix)?;
        };
    }

    // Get the env name to pass to builder
    // Custom env names are used as-is, regular fields use uppercase field name
    let env_name = if let Some(ref custom_env) = field.env {
        custom_env.clone()
    } else {
        field
            .rename
            .as_ref()
            .map(|r| r.to_uppercase())
            .unwrap_or_else(|| ident.to_string().to_uppercase())
    };

    // TypedSecret fields
    if field.typed_secret {
        let classification = classification_tokens(field.classification.as_deref());
        let secret_type = secret_type_tokens(field.secret_type.as_deref());

        return quote! {
            let #ident = builder.get_typed_secret(
                #env_name,
                #secret_type,
                #classification,
            )?;
        };
    }

    // Secret fields
    if field.secret {
        return generate_secret_field(field, &env_name);
    }

    // Regular fields
    generate_regular_field(field, &env_name)
}

/// Generate loading for a secret field with static env name.
fn generate_secret_field(field: &FieldOpts, env_name: &str) -> TokenStream {
    let ident = field.name();
    let is_option = field.is_option_type();

    match (&field.default, is_option) {
        (Some(default), _) => quote! {
            let #ident = builder.get_secret(#env_name)
                .map(|v| v.default(#default))?
                .parse()?;
        },
        (None, true) => quote! {
            let #ident = {
                let value = builder.get_secret(#env_name)?;
                if value.is_set() {
                    Some(value.parse()?)
                } else {
                    None
                }
            };
        },
        (None, false) => quote! {
            let #ident = builder.get_secret(#env_name)?
                .parse()?;
        },
    }
}
/// Generate loading for a regular field with static env name.
fn generate_regular_field(field: &FieldOpts, env_name: &str) -> TokenStream {
    let ident = field.name();
    let is_option = field.is_option_type();

    match (&field.default, is_option) {
        (Some(default), _) => quote! {
            let #ident = builder.get(#env_name)
                .map(|v| v.default(#default))?
                .parse()?;
        },
        (None, true) => quote! {
            let #ident = {
                let value = builder.get(#env_name)?;
                if value.is_set() {
                    Some(value.parse()?)
                } else {
                    None
                }
            };
        },
        (None, false) => quote! {
            let #ident = builder.get(#env_name)?
                .parse()?;
        },
    }
}

/// Convert classification string to token stream.
fn classification_tokens(classification: Option<&str>) -> TokenStream {
    let variant = match classification.map(|s| s.to_lowercase()).as_deref() {
        Some("public") => format_ident!("Public"),
        Some("internal") => format_ident!("Internal"),
        Some("restricted") => format_ident!("Restricted"),
        _ => format_ident!("Confidential"), // Default
    };

    quote! {
        ::octarine::crypto::secrets::Classification::#variant
    }
}

/// Convert secret_type string to token stream.
fn secret_type_tokens(secret_type: Option<&str>) -> TokenStream {
    let variant = match secret_type.map(|s| s.to_lowercase()).as_deref() {
        Some("apikey") => format_ident!("ApiKey"),
        Some("password") => format_ident!("Password"),
        Some("authtoken") => format_ident!("AuthToken"),
        Some("refreshtoken") => format_ident!("RefreshToken"),
        Some("encryptionkey") => format_ident!("EncryptionKey"),
        Some("privatekey") => format_ident!("PrivateKey"),
        Some("keyencryptionkey") => format_ident!("KeyEncryptionKey"),
        Some("masterkey") => format_ident!("MasterKey"),
        Some("databasecredential") => format_ident!("DatabaseCredential"),
        Some("certificatekey") => format_ident!("CertificateKey"),
        Some("hmackey") => format_ident!("HmacKey"),
        Some("webhooksecret") => format_ident!("WebhookSecret"),
        Some("sshkey") => format_ident!("SshKey"),
        _ => format_ident!("Generic"), // Default
    };

    quote! {
        ::octarine::crypto::secrets::SecretType::#variant
    }
}
